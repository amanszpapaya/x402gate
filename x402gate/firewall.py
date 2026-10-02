"""Firewall: installs policy enforcement on an x402Client via a requirements filter and lifecycle hooks."""

from __future__ import annotations

import logging
import threading
from contextvars import ContextVar
from types import SimpleNamespace
from typing import Any

# Per-task, so concurrent payments can't cross reservations between hooks.
_PENDING_RESERVATION: ContextVar[tuple[str, Any] | None] = ContextVar(
    "x402gate_pending_reservation", default=None
)

_INSTALLED_MARKER = "_x402gate_firewall"

_log = logging.getLogger("x402gate")

from .audit import Audit
from .engine import Engine
from .intent import IntentParseError, PaymentIntent, from_context
from .policy import Policy
from .remote_signer import PAYMENT_METADATA
from .state import SpendState


class Firewall:

    def __init__(self, policy: Policy, state: SpendState | None = None,
                 audit: Audit | None = None, caller: str = "agent",
                 expected_payer: str | None = None,
                 verifier: Any | None = None,
                 trust_failure_reports: bool = False,
                 settlement_grace_seconds: int = 120,
                 require_minimum_policy: bool = True) -> None:
        """Settlement reports come from the server and never free budget on their own: the
        chain (verifier) or window expiry decides. trust_failure_reports=True opts out."""
        if require_minimum_policy:
            self.check_minimum_policy(policy)
        self._policy = policy
        self._state = state if state is not None else SpendState()
        self.check_signature_lifetime(policy, self._state)
        self._audit = audit if audit is not None else Audit()
        self._engine = Engine(policy)
        self._caller = caller
        self._expected_payer = expected_payer.lower() if expected_payer else None
        self._verifier = verifier
        self._trust_failure_reports = trust_failure_reports
        if settlement_grace_seconds < 0:
            raise ValueError("settlement_grace_seconds must be non-negative")
        self._grace = int(settlement_grace_seconds)
        # key -> (reservation id, intent, payload pinned for id-based keys so the id can't be reused)
        self._reservations: dict[str, tuple[str, PaymentIntent, Any]] = {}
        self._reservations_lock = threading.Lock()
        self._degraded: str | None = None

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def state(self) -> SpendState:
        return self._state

    @property
    def audit(self) -> Audit:
        return self._audit

    @property
    def degraded(self) -> str | None:
        return self._degraded

    def clear_degraded(self) -> None:
        """Manual on purpose: the firewall can't tell on its own that the cause is fixed."""
        self._degraded = None

    def install(self, client: Any, disable_sdk_spend_controls: bool = True) -> Any:
        """Idempotent; refuses a second Firewall on the same client (it would double count).

        SDK spend controls are disabled because they filter before any hook and bypass the audit.
        """
        installed = getattr(client, _INSTALLED_MARKER, None)
        if installed is self:
            return client
        if installed is not None:
            raise ValueError("this client already has a different firewall installed")

        if disable_sdk_spend_controls and hasattr(client, "set_spend_controls"):
            client.set_spend_controls(False)

        if hasattr(client, "register_policy"):
            client.register_policy(self.filter_requirements)

        client.on_before_payment_creation(self.before_payment_creation)
        client.on_after_payment_creation(self.after_payment_creation)
        client.on_payment_creation_failure(self.payment_creation_failure)
        client.on_payment_response(self.payment_response)
        setattr(client, _INSTALLED_MARKER, self)
        return client

    def filter_requirements(self, x402_version: int,
                            requirements: list[Any]) -> list[Any]:
        """Advisory and stateless. If nothing complies the list is returned unchanged, so the
        before-hook produces an audited denial instead of an opaque SDK error."""
        compliant: list[Any] = []
        for requirement in requirements:
            try:
                candidate = from_context(
                    SimpleNamespace(selected_requirements=requirement, payment_required=None),
                    caller=self._caller,
                )
            except IntentParseError:
                continue
            if self._engine.decide_payment(candidate, self._state)["allow"]:
                compliant.append(requirement)
        return compliant if compliant else list(requirements)

    async def before_payment_creation(self, context: Any) -> Any:
        from x402.schemas.hooks import AbortResult

        PAYMENT_METADATA.set(None)
        if self._degraded is not None:
            reason = f"firewall degraded, refusing payment: {self._degraded}"
            self._safe_audit_decision(
                {"allow": False, "reason": reason, "rule": "degraded"}, intent=None
            )
            return AbortResult(reason=reason)

        self.reconcile()

        try:
            intent = from_context(context, caller=self._caller)
        except IntentParseError as exc:
            reason = f"could not parse payment requirements: {exc}"
            self._safe_audit_decision(
                {"allow": False, "reason": reason, "rule": "intent_parse"}, intent=None
            )
            return AbortResult(reason=reason)

        verdict, reservation_id = self._state.authorize_payment(
            decide_fn=lambda: self._engine.decide_payment(intent, self._state),
            caller=intent.caller,
            recipient=intent.recipient,
            amount_atomic=intent.amount_atomic,
            timeout_seconds=(intent.max_timeout_seconds or 600) + self._grace,
            hold_until_verified=True,
            network=intent.network,
            asset=intent.asset,
            resource=intent.resource or "",
        )

        try:
            self._audit.record_decision(intent, verdict, reservation_id)
        except RuntimeError as exc:
            if reservation_id is not None:
                self._state.release(reservation_id)
            return AbortResult(reason=f"audit unavailable, refusing payment: {exc}")

        if not verdict["allow"]:
            return AbortResult(reason=f"{verdict['rule']}: {verdict['reason']}")
        _PENDING_RESERVATION.set((reservation_id, intent))
        PAYMENT_METADATA.set({"resource": intent.resource, "caller": self._caller})
        return None

    async def after_payment_creation(self, context: Any) -> None:
        PAYMENT_METADATA.set(None)
        pending = _PENDING_RESERVATION.get()
        if pending is None:
            return
        _PENDING_RESERVATION.set(None)
        reservation_id, intent = pending
        payload = getattr(context, "payment_payload", None)
        key = self._payload_key(payload)
        if key is None:
            return
        with self._reservations_lock:
            self._reservations[key] = (reservation_id, intent,
                                       payload if key.startswith("id:") else None)
        if not key.startswith("id:"):          # object ids don't survive a restart
            try:
                self._state.bind_reference(
                    reservation_id, key,
                    valid_before=self._valid_before(getattr(context, "payment_payload", None)))
            except KeyError:
                pass

    async def payment_creation_failure(self, context: Any) -> None:
        """Signing failed, so the after-hook won't run. Returning None lets the SDK re-raise."""
        PAYMENT_METADATA.set(None)
        pending = _PENDING_RESERVATION.get()
        if pending is None:
            return None
        _PENDING_RESERVATION.set(None)
        reservation_id, _intent = pending
        try:
            self._state.release(reservation_id)
        except (KeyError, ValueError):
            pass
        error = getattr(context, "error", None)
        try:
            self._audit.record_release(reservation_id, f"payment creation failed: {error}")
        except RuntimeError as exc:
            self._degrade(f"audit unavailable after a payment creation failure: {exc}")
        return None

    async def payment_response(self, context: Any) -> None:
        """Never raises (the payment already happened); failures degrade the firewall instead."""
        try:
            self._settle(context)
        except Exception as exc:  # noqa: BLE001
            self._degrade(f"settlement handling failed ({type(exc).__name__}: {exc})")
        return None

    def _settle(self, context: Any) -> None:
        """Ledger first, audit second, so an audit failure can't leave money uncounted."""
        key = self._payload_key(getattr(context, "payment_payload", None))
        with self._reservations_lock:
            known = self._reservations.pop(key, None) if key else None
        reservation_id, intent = known[:2] if known else (None, None)
        if reservation_id is None and key:
            reservation_id = self._state.find_reservation_by_ref(key)

        settle = getattr(context, "settle_response", None)
        error = getattr(context, "error", None)
        success = bool(getattr(settle, "success", False)) and error is None
        transaction = getattr(settle, "transaction", None) or None

        if not success:
            reported = str(getattr(settle, "error_reason", None) or error or "no settle response")
            if self._trust_failure_reports and reservation_id is not None:
                try:
                    self._state.release(reservation_id)
                except (KeyError, ValueError):
                    pass
                self._audit.record_settlement(reservation_id, False, error=reported)
                return
            then = ("verified on-chain" if self._verifier is not None
                    else "its window passes, then counted as spent")
            self._audit.record_settlement(
                reservation_id, False,
                error=f"{reported} — reported by the server, not trusted; "
                      f"held until {then}",
            )
            return

        settled_amount = self._parse_amount(getattr(settle, "amount", None))
        payer = getattr(settle, "payer", None)

        # Detective only, and the payer field is server-reported.
        problems: list[str] = []
        if self._expected_payer and payer and payer.lower() != self._expected_payer:
            problems.append(f"UNEXPECTED PAYER: settled from {payer}, "
                            f"expected {self._expected_payer}")

        status = (self._state.reservation_status(reservation_id)
                  if reservation_id is not None else None)

        if status == "committed":
            return                              # duplicate delivery

        if status == "pending":
            scheme = (intent.scheme if intent is not None
                      else str(getattr(getattr(context, "requirements", None), "scheme", "")))
            authorized = self._state.reserved_amount(reservation_id)
            if settled_amount is not None and settled_amount > authorized:
                self._state.commit(reservation_id, payer=payer, transaction=transaction)
                problems.insert(0, f"SETTLEMENT EXCEEDED AUTHORIZATION: server reported "
                                   f"{settled_amount}, authorized {authorized}")
            elif scheme != "upto":
                # EIP-3009 exact moves exactly the signed value, whatever the server reports.
                if settled_amount is not None and settled_amount != authorized:
                    problems.insert(0, f"SETTLEMENT AMOUNT MISMATCH: server reported "
                                       f"{settled_amount}, but an exact authorization moves "
                                       f"{authorized}; counted {authorized}")
                self._state.commit(reservation_id, payer=payer, transaction=transaction)
            else:
                # upto amounts are server-reported: residual risk with untrusted sellers.
                self._state.commit(reservation_id, settled_amount, payer=payer,
                                   transaction=transaction)
            self._audit.record_settlement(
                reservation_id, True, transaction=transaction,
                settled_amount_atomic=settled_amount,
                error="; ".join(problems) or None,
            )
            return

        # No live reservation but the money moved (late, or after a restart): count it.
        if transaction and self._state.has_settled_transaction(transaction):
            return

        if intent is not None:
            label = "LATE SETTLEMENT: reservation expired before the settlement arrived"
            recipient, network, asset = intent.recipient, intent.network, intent.asset
            resource, asked = intent.resource or "", intent.amount_atomic
        else:
            label = "UNMATCHED SETTLEMENT: no reservation found for this payment"
            requirements = getattr(context, "requirements", None)
            recipient = getattr(requirements, "pay_to", "") or ""
            network = getattr(requirements, "network", "") or ""
            asset = getattr(requirements, "asset", "") or ""
            asked = self._parse_amount(getattr(requirements, "amount", None)) or 0
            resource_info = getattr(getattr(context, "payment_required", None), "resource", None)
            resource = str(getattr(resource_info, "url", "") or "")

        recorded = settled_amount if settled_amount is not None else asked
        if settled_amount is not None and settled_amount > asked:
            problems.insert(0, f"SETTLEMENT EXCEEDED AUTHORIZATION: settled "
                               f"{settled_amount}, authorized {asked}")
        self._state.record_unreserved_settlement(
            caller=self._caller, recipient=recipient, amount_atomic=recorded,
            network=network, asset=asset, resource=resource, payer=payer,
            transaction=transaction, asked_amount_atomic=asked,
        )
        self._audit.record_settlement(
            reservation_id, True, transaction=transaction,
            settled_amount_atomic=settled_amount,
            error="; ".join([label, *problems]),
        )

    @staticmethod
    def check_minimum_policy(policy: Policy) -> None:
        kinds = {rule["kind"] for rule in policy.rules()}
        missing = []
        if Policy.KIND_NETWORK_ALLOWLIST not in kinds:
            missing.append("a network allowlist (nothing else stops a mainnet payment)")
        if Policy.KIND_ASSET_ALLOWLIST not in kinds:
            missing.append("an asset allowlist (otherwise any token the wallet holds, "
                           "in any units, can be spent)")
        if Policy.KIND_MAX_PER_PAYMENT not in kinds:
            missing.append("a per-payment cap")
        if Policy.KIND_MAX_AUTHORIZATION_WINDOW not in kinds:
            missing.append("an authorization window cap (otherwise a signature can stay "
                           "valid for years, outliving every later policy change)")
        if missing:
            raise ValueError(
                "policy is missing " + " and ".join(missing)
                + ". Pass require_minimum_policy=False only if you mean it."
            )

    @staticmethod
    def check_signature_lifetime(policy: Policy, state: SpendState) -> None:
        """A signature must not outlive its ledger entry, or a live nonce ages out and can be re-signed."""
        for rule in policy.rules():
            if (rule["kind"] == Policy.KIND_MAX_AUTHORIZATION_WINDOW
                    and rule["max_seconds"] > state.window_seconds):
                raise ValueError(f"max_authorization_window ({rule['max_seconds']}s) exceeds the "
                                 f"ledger window ({state.window_seconds}s)")

    @staticmethod
    def _payload_key(payload: Any) -> str | None:
        if payload is None:
            return None
        inner = getattr(payload, "payload", None)
        if isinstance(inner, dict):
            for path in (("authorization", "nonce"), ("nonce",), ("signature",)):
                value: Any = inner
                for part in path:
                    value = value.get(part) if isinstance(value, dict) else None
                    if value is None:
                        break
                if isinstance(value, str) and value:
                    return value
        return f"id:{id(payload)}"

    @staticmethod
    def _parse_amount(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _safe_audit_decision(self, verdict: dict[str, Any],
                             intent: PaymentIntent | None) -> None:
        try:
            self._audit.record_decision(intent, verdict)
        except RuntimeError:
            pass

    def reconcile(self) -> dict[str, int]:
        from .chain import reconcile_held
        try:
            counts = reconcile_held(self._state, self._audit, self._verifier, self._expected_payer,
                                    count_unverifiable=True, record=self._safe_record)
            with self._reservations_lock:
                for key in [k for k, v in self._reservations.items()
                            if self._state.reservation_status(v[0]) != "pending"]:
                    del self._reservations[key]
            return counts
        except Exception as exc:  # noqa: BLE001
            self._degrade(f"reconciliation failed ({type(exc).__name__}: {exc})")
            return {"committed": 0, "released": 0, "unknown": 0, "unverified": 0}

    def _safe_record(self, write: Any) -> None:
        try:
            write()
        except RuntimeError as exc:
            self._degrade(f"audit unavailable: {exc}")

    @staticmethod
    def _valid_before(payload: Any) -> int | None:
        inner = getattr(payload, "payload", None)
        auth = inner.get("authorization") if isinstance(inner, dict) else None
        value = auth.get("validBefore") if isinstance(auth, dict) else None
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _degrade(self, reason: str) -> None:
        if self._degraded is None:
            self._degraded = reason
        _log.error("x402 firewall degraded, refusing all payments: %s", reason)
