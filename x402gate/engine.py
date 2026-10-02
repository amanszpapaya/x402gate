"""Engine: evaluates a policy's rules against a payment intent and issues verdicts."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .intent import PaymentIntent
from .policy import Policy
from .state import SpendState


class Engine:

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def decide_payment(self, intent: PaymentIntent, state: SpendState) -> Mapping[str, Any]:
        for rule in self._policy.rules():
            verdict = self.check_rule(rule, intent, state)
            if verdict is not None and not verdict["allow"]:
                return verdict
        return self._allow()

    def find_all_violations(self, intent: PaymentIntent,
                            state: SpendState) -> list[Mapping[str, Any]]:
        violations: list[Mapping[str, Any]] = []
        for rule in self._policy.rules():
            verdict = self.check_rule(rule, intent, state)
            if verdict is not None and not verdict["allow"]:
                violations.append(verdict)
        return violations

    def check_rule(self, rule: dict[str, Any], intent: PaymentIntent,
                   state: SpendState) -> Mapping[str, Any] | None:
        """Return a denial or None (abstain); a rule never allows, and any exception denies."""
        rule_name = "<unreadable rule>"
        try:
            rule_name = rule["name"]
            kind = rule["kind"]
            reason: str | None = None

            if kind == Policy.KIND_MAX_PER_PAYMENT:
                if intent.amount_atomic > rule["max_atomic"]:
                    reason = f"amount {intent.amount_atomic} exceeds per-payment cap {rule['max_atomic']}"

            elif kind == Policy.KIND_RECIPIENT_ALLOWLIST:
                if intent.recipient.lower() not in rule["allowed"]:
                    reason = f"recipient {intent.recipient} is not on the allowlist"

            elif kind == Policy.KIND_NETWORK_ALLOWLIST:
                if intent.network.lower() not in rule["allowed"]:
                    reason = f"network {intent.network} is not on the allowlist"

            elif kind == Policy.KIND_ASSET_ALLOWLIST:
                if intent.asset.lower() not in rule["allowed"]:
                    reason = f"asset {intent.asset} is not on the allowlist"

            elif kind == Policy.KIND_SCHEME_ALLOWLIST:
                if intent.scheme.lower() not in rule["allowed"]:
                    reason = f"scheme {intent.scheme} is not on the allowlist"

            elif kind == Policy.KIND_TOTAL_BUDGET:
                projected = state.spent_total() + intent.amount_atomic
                if projected > rule["max_atomic"]:
                    reason = (f"total spend would reach {projected}, "
                              f"over cap {rule['max_atomic']}")

            elif kind == Policy.KIND_RESOURCE_BUDGET:
                if intent.resource:
                    projected = state.spent_on(intent.resource) + intent.amount_atomic
                    if projected > rule["max_atomic"]:
                        reason = (f"resource {intent.resource} would reach {projected}, "
                                  f"over cap {rule['max_atomic']}")

            elif kind == Policy.KIND_RECIPIENT_BUDGET:
                projected = state.spent_to(intent.recipient) + intent.amount_atomic
                if projected > rule["max_atomic"]:
                    reason = (f"recipient {intent.recipient} would reach {projected}, "
                              f"over cap {rule['max_atomic']}")

            elif kind == Policy.KIND_VELOCITY:
                recent = state.payment_count_total(rule["window_seconds"])
                if recent >= rule["max_count"]:
                    reason = (f"already made {recent} payment(s) in the last "
                              f"{rule['window_seconds']}s (limit {rule['max_count']})")

            elif kind == Policy.KIND_MAX_AUTHORIZATION_WINDOW:
                window = intent.max_timeout_seconds
                if window <= 0:
                    reason = "server did not state a settlement window (max_timeout_seconds)"
                elif window > rule["max_seconds"]:
                    reason = (f"settlement window {window}s exceeds maximum "
                              f"{rule['max_seconds']}s")

            elif kind == Policy.KIND_PRICE_DRIFT:
                if intent.resource and intent.amount_atomic >= (rule["min_amount_atomic"] or 0):
                    baseline = state.price_baseline(
                        intent.resource, intent.network, intent.asset,
                        min_observations=rule["min_count"],
                    )
                    # A 0 baseline means no baseline; dividing by it would lock the endpoint.
                    if baseline is not None and baseline > 0:
                        ceiling = baseline * rule["max_multiple"]
                        if intent.amount_atomic > ceiling:
                            reason = (f"price {intent.amount_atomic} is "
                                      f"{intent.amount_atomic / baseline:.1f}x the median "
                                      f"{baseline} paid for {intent.resource} "
                                      f"(limit {rule['max_multiple']}x)")

            elif kind == Policy.KIND_CUSTOM:
                reason = rule["predicate"](intent, state)

            else:
                reason = f"unknown rule kind: {kind!r}"

            if reason is not None:
                return self._deny(rule_name, reason)
            return None

        except Exception as exc:
            # Not BaseException: KeyboardInterrupt and SystemExit must propagate.
            return self._deny(
                rule_name,
                f"rule evaluation failed ({type(exc).__name__}: {exc})",
            )

    # Build the dict inline: the proxy is a view, so any other reference could mutate the verdict.
    def _deny(self, rule_name: str, reason: str) -> Mapping[str, Any]:
        return MappingProxyType({"allow": False, "reason": reason, "rule": rule_name})

    def _allow(self, reason: str = "passed all rules",
               rule_name: str = "engine") -> Mapping[str, Any]:
        return MappingProxyType({"allow": True, "reason": reason, "rule": rule_name})
