"""SignerService: holds the key outside the agent's process and signs only what the policy allows."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import stat
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

# Module level: FastAPI resolves the postponed `Request` annotation from these globals.
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .audit import Audit
from .chain import ChainVerifier, reconcile_held
from .engine import Engine
from .firewall import Firewall
from .intent import (TRANSFER_WITH_AUTHORIZATION, TRANSFER_WITH_AUTHORIZATION_FIELDS,
                     IntentParseError, PaymentIntent, from_typed_data)
from .policy import Policy
from .state import SpendState

_log = logging.getLogger("x402gate.signer")

_MAX_REQUEST_BYTES = 64 * 1024


class SignerService:

    def __init__(self, account: Any, policy: Policy, state: SpendState, audit: Audit, *,
                 verifier: ChainVerifier | None = None,
                 settlement_grace_seconds: int = 300,
                 clock: Callable[[], float] | None = None,
                 alert: Callable[[str], None] | None = None,
                 require_minimum_policy: bool = True) -> None:
        if require_minimum_policy:
            Firewall.check_minimum_policy(policy)
        Firewall.check_signature_lifetime(policy, state)
        if settlement_grace_seconds < 0:
            raise ValueError("settlement_grace_seconds must be non-negative")
        self._account = account
        self._policy = policy
        self._state = state
        self._audit = audit
        self._engine = Engine(policy)
        self._verifier = verifier
        self._grace = int(settlement_grace_seconds)
        self._clock = clock or time.time
        self._alert = alert
        self._degraded: str | None = None

    @property
    def address(self) -> str:
        return self._account.address

    @property
    def degraded(self) -> str | None:
        """Cleared only by a restart: the agent can reach the socket, so no endpoint may clear it."""
        return self._degraded

    @property
    def state(self) -> SpendState:
        return self._state

    @property
    def audit(self) -> Audit:
        return self._audit

    def sign(self, request: dict[str, Any]) -> dict[str, Any]:
        """Never raises. Returns {"allow": True, "signature": ...} or {"allow": False, "rule", "reason"}."""
        try:
            return self._sign_request(request)
        except Exception as exc:  # noqa: BLE001
            _log.exception("unexpected error while judging a signing request")
            return self._deny("internal_error", f"internal error, refusing to sign: "
                                                f"{type(exc).__name__}", None)

    def _sign_request(self, request: Any) -> dict[str, Any]:
        if self._degraded is not None:
            return self._deny("degraded", f"signer degraded: {self._degraded}", None)
        if not isinstance(request, dict):
            return self._deny("intent_parse", "request must be a JSON object", None)

        metadata = request.get("metadata")
        with self._state.transaction():
            try:
                intent = from_typed_data(
                    request.get("domain"), request.get("types"),
                    request.get("primaryType"), request.get("message"),
                    signer_address=self.address,
                    metadata=metadata if isinstance(metadata, dict) else None,
                    clock=self._clock,
                )
            except IntentParseError as exc:
                return self._deny("intent_parse", f"could not accept signing request: {exc}",
                                  None)

            nonce = intent.raw["signable"]["message"]["nonce"]
            # A nonce may settle once; signing it twice would create two live authorizations.
            if self._state.find_reservation_by_ref(nonce) is not None:
                return self._deny("duplicate_nonce", f"nonce {nonce} was already signed", intent)

            verdict = self._engine.decide_payment(intent, self._state)
            if not verdict["allow"]:
                self._record_denial(intent, verdict)
                return {"allow": False, "rule": verdict["rule"], "reason": verdict["reason"]}

            reservation_id = self._state.reserve(
                caller=intent.caller, recipient=intent.recipient,
                amount_atomic=intent.amount_atomic,
                timeout_seconds=max(1, intent.max_timeout_seconds + self._grace),
                network=intent.network, asset=intent.asset,
                resource=intent.resource or "",
                hold_until_verified=self._verifier is not None,
            )
            self._state.bind_reference(
                reservation_id, nonce,
                valid_before=intent.raw["signable"]["message"]["validBefore"])

            try:
                self._audit.record_decision(intent, verdict, reservation_id)
            except RuntimeError as exc:
                self._state.release(reservation_id)
                return {"allow": False, "rule": "audit",
                        "reason": f"audit unavailable, refusing to sign: {exc}"}

            try:
                signature = self._sign(intent)
            except Exception as exc:  # noqa: BLE001
                self._state.release(reservation_id)
                self._safe(lambda: self._audit.record_release(
                    reservation_id, f"signing failed: {exc}"))
                return {"allow": False, "rule": "signing", "reason": f"signing failed: {exc}"}

            # Without a verifier the signature is the spend.
            if self._verifier is None:
                try:
                    self._state.commit(reservation_id)
                except Exception as exc:  # noqa: BLE001
                    # Withhold the signature: a payment the ledger can't count must not be made.
                    self._degrade(f"ledger commit failed after signing: {exc}")
                    return {"allow": False, "rule": "degraded",
                            "reason": "ledger unavailable, signature withheld"}

            return {"allow": True, "signature": signature, "reservation_id": reservation_id}

    def _sign(self, intent: PaymentIntent) -> str:
        # Signs the normalised copy that was judged, never the request as sent.
        signable = intent.raw["signable"]
        message = dict(signable["message"])
        message["nonce"] = bytes.fromhex(message["nonce"][2:])
        signed = self._account.sign_typed_data(
            domain_data=dict(signable["domain"]),
            message_types={TRANSFER_WITH_AUTHORIZATION: [
                {"name": name, "type": kind} for name, kind in TRANSFER_WITH_AUTHORIZATION_FIELDS]},
            message_data=message,
        )
        return "0x" + bytes(signed.signature).hex()

    def reconcile(self) -> dict[str, int]:
        if self._verifier is None:
            return {"committed": 0, "released": 0, "unknown": 0, "unverified": 0}
        return reconcile_held(self._state, self._audit, self._verifier, self.address,
                              count_unverifiable=False, record=self._safe)

    def status(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "degraded": self._degraded,
            "spent_total": self._state.spent_total(),
            "outstanding": len(self._state.outstanding()),
            "awaiting_verification": len(self._state.awaiting_verification()),
            "chain_verification": self._verifier is not None,
            "rules": [rule["name"] for rule in self._policy.rules()],
        }

    def _deny(self, rule: str, reason: str, intent: PaymentIntent | None) -> dict[str, Any]:
        self._record_denial(intent, {"allow": False, "rule": rule, "reason": reason})
        return {"allow": False, "rule": rule, "reason": reason}

    def _record_denial(self, intent: PaymentIntent | None, verdict: Any) -> None:
        try:
            self._audit.record_decision(intent, verdict)
        except RuntimeError:
            pass

    def _safe(self, record: Callable[[], Any]) -> None:
        try:
            record()
        except RuntimeError as exc:
            self._degrade(f"audit unavailable: {exc}")

    def _degrade(self, reason: str) -> None:
        if self._degraded is None:
            self._degraded = reason
        _log.error("x402gate signer degraded, refusing to sign: %s", reason)
        if self._alert is not None:
            try:
                self._alert(reason)
            except Exception:  # noqa: BLE001
                _log.exception("degrade alert failed")


def create_app(service: SignerService, reconcile_interval_seconds: float = 30.0):
    """Only /v1/address, /v1/status and /v1/sign: nothing the agent can reach may loosen control."""

    @asynccontextmanager
    async def lifespan(_app):
        task = None
        if reconcile_interval_seconds > 0:
            async def loop():
                while True:
                    await asyncio.sleep(reconcile_interval_seconds)
                    try:
                        await run_in_threadpool(service.reconcile)
                    except Exception:  # noqa: BLE001
                        _log.exception("reconcile pass failed")
            task = asyncio.create_task(loop())
        yield
        if task is not None:
            task.cancel()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/v1/address")
    async def address():
        return {"address": service.address}

    @app.get("/v1/status")
    async def status():
        return await run_in_threadpool(service.status)

    @app.post("/v1/sign")
    async def sign(request: Request):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > _MAX_REQUEST_BYTES:
                return JSONResponse({"allow": False, "rule": "request_too_large",
                                     "reason": f"request exceeds {_MAX_REQUEST_BYTES} bytes"},
                                    status_code=413)
        try:
            body = json.loads(raw)
        except Exception:  # noqa: BLE001
            body = None
        result = await run_in_threadpool(service.sign, body)
        return JSONResponse(result, status_code=200 if result.get("allow") else 403)

    return app


def bind_socket(socket_path: str | os.PathLike[str], mode: int = 0o660) -> socket.socket:
    """The socket's permission bits are the access control: whoever can write it can ask to sign."""
    path = Path(socket_path)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    parent = path.parent.stat()
    # A pre-created directory (say, under /tmp) would hand its owner control of the socket.
    if hasattr(os, "geteuid") and parent.st_uid != os.geteuid():
        raise ValueError(f"socket directory {path.parent} is owned by uid {parent.st_uid}, "
                         f"not by this service")
    parent_mode = stat.S_IMODE(parent.st_mode)
    if parent_mode & 0o022:
        # A writable directory lets others swap the socket or plant a symlink for chmod.
        raise ValueError(f"socket directory {path.parent} is writable by group or others "
                         f"({oct(parent_mode)}); use a directory only the service can write")
    if path.exists() or path.is_symlink():
        if not stat.S_ISSOCK(path.lstat().st_mode):
            raise ValueError(f"{path} exists and is not a socket; refusing to replace it")
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, mode)
    sock.listen(128)
    return sock


def serve(service: SignerService, socket_path: str | os.PathLike[str],
          reconcile_interval_seconds: float = 30.0, socket_mode: int = 0o660) -> None:
    import uvicorn
    sock = bind_socket(socket_path, socket_mode)
    config = uvicorn.Config(create_app(service, reconcile_interval_seconds),
                            log_level="warning")
    uvicorn.Server(config).run(sockets=[sock])
