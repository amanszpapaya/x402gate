"""Policy: the ordered set of rules the engine enforces, with create/update/delete."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Callable, Iterable

# Custom rule contract: return a deny reason, or None to abstain.
CustomCheck = Callable[..., "str | None"]


class Policy:

    KIND_MAX_PER_PAYMENT = "max_per_payment"
    KIND_RECIPIENT_ALLOWLIST = "recipient_allowlist"
    KIND_NETWORK_ALLOWLIST = "network_allowlist"
    KIND_ASSET_ALLOWLIST = "asset_allowlist"
    KIND_SCHEME_ALLOWLIST = "scheme_allowlist"
    KIND_TOTAL_BUDGET = "total_budget"
    KIND_RECIPIENT_BUDGET = "recipient_budget"
    KIND_RESOURCE_BUDGET = "resource_budget"
    KIND_VELOCITY = "velocity"
    KIND_MAX_AUTHORIZATION_WINDOW = "max_authorization_window"
    KIND_PRICE_DRIFT = "price_drift"
    KIND_CUSTOM = "custom"

    _ALLOWLIST_KINDS = (
        KIND_RECIPIENT_ALLOWLIST, KIND_NETWORK_ALLOWLIST,
        KIND_ASSET_ALLOWLIST, KIND_SCHEME_ALLOWLIST,
    )

    def __init__(self) -> None:
        self._rules: list[dict[str, Any]] = []

    # Read-only copies: mutating a returned rule must not bypass validation.
    def rules(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(MappingProxyType(dict(r)) for r in self._rules)

    def get_rule(self, name: str) -> Mapping[str, Any] | None:
        rule = self._find(name)
        return MappingProxyType(dict(rule)) if rule is not None else None

    def has_rule(self, name: str) -> bool:
        return self._find(name) is not None

    def _find(self, name: str) -> dict[str, Any] | None:
        return next((r for r in self._rules if r["name"] == name), None)

    def add_max_per_payment(self, max_atomic: int, name: str = "max_per_payment") -> None:
        self._insert(self._build(
            name, self.KIND_MAX_PER_PAYMENT, max_atomic=max_atomic,
            description=f"single payment must not exceed {max_atomic} atomic units",
        ))

    def add_recipient_allowlist(self, allowed: Iterable[str],
                                name: str = "recipient_allowlist") -> None:
        allowed = frozenset(allowed)
        self._insert(self._build(
            name, self.KIND_RECIPIENT_ALLOWLIST, allowed=allowed,
            description=f"recipient must be one of {len(allowed)} allowlisted address(es)",
        ))

    def add_network_allowlist(self, allowed: Iterable[str],
                              name: str = "network_allowlist") -> None:
        allowed = frozenset(allowed)
        self._insert(self._build(
            name, self.KIND_NETWORK_ALLOWLIST, allowed=allowed,
            description=f"network must be one of {sorted(a.lower() for a in allowed)}",
        ))

    def add_asset_allowlist(self, allowed: Iterable[str],
                            name: str = "asset_allowlist") -> None:
        allowed = frozenset(allowed)
        self._insert(self._build(
            name, self.KIND_ASSET_ALLOWLIST, allowed=allowed,
            description=f"asset must be one of {len(allowed)} allowlisted address(es)",
        ))

    def add_scheme_allowlist(self, allowed: Iterable[str],
                             name: str = "scheme_allowlist") -> None:
        allowed = frozenset(allowed)
        self._insert(self._build(
            name, self.KIND_SCHEME_ALLOWLIST, allowed=allowed,
            description=f"scheme must be one of {sorted(a.lower() for a in allowed)}",
        ))

    def add_total_budget(self, max_atomic: int, name: str = "total_budget") -> None:
        """Cap all spend in the window. Identity-free on purpose: caller labels are agent-supplied."""
        self._insert(self._build(
            name, self.KIND_TOTAL_BUDGET, max_atomic=max_atomic,
            description=f"total spend per window must not exceed {max_atomic}",
        ))

    def add_resource_budget(self, max_atomic: int, name: str = "resource_budget") -> None:
        """Advisory against a hostile counterparty: the server (or, with the signer, the agent)
        chooses the resource URL. The same holds for price drift."""
        self._insert(self._build(
            name, self.KIND_RESOURCE_BUDGET, max_atomic=max_atomic,
            description=f"cumulative spend per resource must not exceed {max_atomic}",
        ))

    def add_recipient_budget(self, max_atomic: int, name: str = "recipient_budget") -> None:
        self._insert(self._build(
            name, self.KIND_RECIPIENT_BUDGET, max_atomic=max_atomic,
            description=f"cumulative spend to any one recipient must not exceed {max_atomic}",
        ))

    def add_velocity(self, max_payments: int, within_seconds: int,
                     name: str = "velocity") -> None:
        self._insert(self._build(
            name, self.KIND_VELOCITY, max_count=max_payments, window_seconds=within_seconds,
            description=f"at most {max_payments} payment(s) per {within_seconds}s overall",
        ))

    def add_max_authorization_window(self, max_seconds: int,
                                     name: str = "max_authorization_window") -> None:
        self._insert(self._build(
            name, self.KIND_MAX_AUTHORIZATION_WINDOW, max_seconds=max_seconds,
            description=f"server settlement window must be stated and at most {max_seconds}s",
        ))

    def add_price_drift(self, max_multiple: float, min_observations: int = 5,
                        min_amount_atomic: int = 0,
                        name: str = "price_drift") -> None:
        """Abstains below min_observations, so new endpoints rely on the per-payment cap."""
        if max_multiple <= 0:
            raise ValueError("price_drift requires a positive max_multiple")
        self._insert(self._build(
            name, self.KIND_PRICE_DRIFT, max_multiple=float(max_multiple),
            min_count=int(min_observations), max_atomic=None,
            min_amount_atomic=int(min_amount_atomic),
            description=(f"price must not exceed {max_multiple}x the median of the last "
                         f"{min_observations}+ accepted prices for this resource"),
        ))

    def add_custom(self, name: str, predicate: CustomCheck, description: str = "") -> None:
        self._insert(self._build(
            name, self.KIND_CUSTOM, predicate=predicate,
            description=description or f"custom rule: {name}",
        ))

    def update_rule(self, name: str, **changes: Any) -> None:
        for i, existing in enumerate(self._rules):
            if existing["name"] == name:
                merged = {**existing, **changes, "name": name, "kind": existing["kind"]}
                self._rules[i] = self._build(
                    name, existing["kind"],
                    max_atomic=merged.get("max_atomic"),
                    allowed=merged.get("allowed") or frozenset(),
                    predicate=merged.get("predicate"),
                    max_count=merged.get("max_count"),
                    window_seconds=merged.get("window_seconds"),
                    max_seconds=merged.get("max_seconds"),
                    max_multiple=merged.get("max_multiple"),
                    min_count=merged.get("min_count"),
                    min_amount_atomic=merged.get("min_amount_atomic"),
                    description=changes.get("description", existing["description"]),
                )
                return
        raise KeyError(f"no rule named {name!r} to update")

    def remove_rule(self, name: str) -> None:
        rule = self._find(name)
        if rule is None:
            raise KeyError(f"no rule named {name!r} to remove")
        self._rules.remove(rule)

    def _insert(self, rule: dict[str, Any]) -> None:
        if self.has_rule(rule["name"]):
            raise ValueError(f"policy already has a rule named {rule['name']!r}")
        self._rules.append(rule)

    def _build(self, name: str, kind: str, *, max_atomic: int | None = None,
               allowed: frozenset[str] = frozenset(),
               predicate: CustomCheck | None = None,
               max_count: int | None = None, window_seconds: int | None = None,
               max_seconds: int | None = None, max_multiple: float | None = None,
               min_count: int | None = None, min_amount_atomic: int | None = None,
               description: str = "") -> dict[str, Any]:
        if kind in (self.KIND_MAX_PER_PAYMENT, self.KIND_TOTAL_BUDGET,
                    self.KIND_RECIPIENT_BUDGET, self.KIND_RESOURCE_BUDGET):
            if max_atomic is None or max_atomic < 0:
                raise ValueError(f"{kind} requires a non-negative max_atomic")
        elif kind in self._ALLOWLIST_KINDS:
            # Lowercase so checksum or mixed casing can't slip past the list.
            allowed = frozenset(a.lower() for a in allowed)
        elif kind == self.KIND_VELOCITY:
            if max_count is None or max_count < 0:
                raise ValueError("velocity requires a non-negative max_count")
            if window_seconds is None or window_seconds <= 0:
                raise ValueError("velocity requires a positive window_seconds")
        elif kind == self.KIND_MAX_AUTHORIZATION_WINDOW:
            if max_seconds is None or max_seconds <= 0:
                raise ValueError("max_authorization_window requires a positive max_seconds")
        elif kind == self.KIND_PRICE_DRIFT:
            if max_multiple is None or max_multiple <= 0:
                raise ValueError("price_drift requires a positive max_multiple")
            if min_count is None or min_count < 1:
                raise ValueError("price_drift requires min_observations >= 1")
            if min_amount_atomic is None or min_amount_atomic < 0:
                raise ValueError("price_drift requires a non-negative min_amount_atomic")
        elif kind == self.KIND_CUSTOM:
            if predicate is None:
                raise ValueError("custom rule requires a predicate")
        else:
            raise ValueError(f"unknown rule kind: {kind!r}")

        return {
            "name": name, "kind": kind, "description": description,
            "max_atomic": max_atomic, "allowed": allowed, "predicate": predicate,
            "max_count": max_count, "window_seconds": window_seconds,
            "max_seconds": max_seconds, "max_multiple": max_multiple,
            "min_count": min_count, "min_amount_atomic": min_amount_atomic,
        }
