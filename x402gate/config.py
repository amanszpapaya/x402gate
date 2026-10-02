"""Config: strict TOML configuration for the firewall and signer; unknown keys are errors."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from .policy import Policy

_SERVICE_KEYS = {
    "key_file", "socket", "journal", "audit", "rpc_urls", "settlement_grace_seconds",
    "window_seconds", "reconcile_interval_seconds", "alert_command", "audit_strict",
    "socket_mode", "release_block",
}
_REQUIRED_SERVICE_KEYS = {"key_file", "socket", "journal", "audit"}
_POLICY_KEYS = {
    "networks", "assets", "schemes", "recipients", "max_per_payment", "total_budget",
    "recipient_budget", "resource_budget", "max_authorization_window", "velocity",
    "price_drift",
}
_REQUIRED_POLICY_KEYS = {"networks", "max_per_payment"}
_VELOCITY_KEYS = {"max_payments", "within_seconds"}
_DRIFT_KEYS = {"max_multiple", "min_observations", "min_amount_atomic"}


class Config:

    def __init__(self, data: dict[str, Any], base_dir: str | os.PathLike[str] = ".") -> None:
        self._base = Path(base_dir).resolve()
        self._check_keys("top level", data, {"service", "policy"}, {"policy"})
        self._service = data.get("service", {})
        self._policy = data["policy"]
        if not isinstance(self._policy, dict):
            raise ValueError("[policy] must be a table")
        if self._service:
            if not isinstance(self._service, dict):
                raise ValueError("[service] must be a table")
            self._check_keys("[service]", self._service, _SERVICE_KEYS, _REQUIRED_SERVICE_KEYS)
        self._check_keys("[policy]", self._policy, _POLICY_KEYS, _REQUIRED_POLICY_KEYS)
        self._validate_policy()
        self._validate_service()
        window = self._policy.get("max_authorization_window")
        if self._service and window is not None and window > self.window_seconds:
            raise ValueError(f"policy.max_authorization_window ({window}s) exceeds the ledger window "
                             f"service.window_seconds ({self.window_seconds}s)")

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "Config":
        path = Path(path)
        with open(path, "rb") as fh:
            try:
                data = tomllib.load(fh)
            except tomllib.TOMLDecodeError as exc:
                raise ValueError(f"{path}: not valid TOML: {exc}") from exc
        return cls(data, base_dir=path.parent)

    def build_policy(self) -> Policy:
        p, policy = self._policy, Policy()
        policy.add_network_allowlist(p["networks"])
        if "assets" in p:
            policy.add_asset_allowlist(p["assets"])
        if "schemes" in p:
            policy.add_scheme_allowlist(p["schemes"])
        if "recipients" in p:
            policy.add_recipient_allowlist(p["recipients"])
        policy.add_max_per_payment(p["max_per_payment"])
        if "max_authorization_window" in p:
            policy.add_max_authorization_window(p["max_authorization_window"])
        if "total_budget" in p:
            policy.add_total_budget(p["total_budget"])
        if "recipient_budget" in p:
            policy.add_recipient_budget(p["recipient_budget"])
        if "resource_budget" in p:
            policy.add_resource_budget(p["resource_budget"])
        if "velocity" in p:
            policy.add_velocity(p["velocity"]["max_payments"], p["velocity"]["within_seconds"])
        if "price_drift" in p:
            drift = p["price_drift"]
            policy.add_price_drift(drift["max_multiple"],
                                   min_observations=drift.get("min_observations", 5),
                                   min_amount_atomic=drift.get("min_amount_atomic", 0))
        return policy

    @property
    def has_service(self) -> bool:
        return bool(self._service)

    def path(self, key: str) -> Path:
        """Relative paths resolve against the config file's directory, not the cwd."""
        value = Path(self._require_service(key))
        return value if value.is_absolute() else self._base / value

    @property
    def rpc_urls(self) -> dict[str, str | list[str]]:
        return dict(self._service.get("rpc_urls", {}))

    @property
    def settlement_grace_seconds(self) -> int:
        return self._service.get("settlement_grace_seconds", 300)

    @property
    def release_block(self) -> str:
        return self._service.get("release_block", "finalized")

    @property
    def window_seconds(self) -> int:
        return self._service.get("window_seconds", 86_400)

    @property
    def reconcile_interval_seconds(self) -> int:
        return self._service.get("reconcile_interval_seconds", 30)

    @property
    def audit_strict(self) -> bool:
        return self._service.get("audit_strict", True)

    @property
    def socket_mode(self) -> int:
        return int(str(self._service.get("socket_mode", "660")), 8)

    def load_account(self) -> Any:
        from eth_account import Account
        path = self.path("key_file")
        check_key_file_permissions(path)
        key = path.read_text().strip()
        if not key:
            raise ValueError(f"{path} is empty")
        return Account.from_key(key if key.startswith("0x") else "0x" + key)

    def alert(self) -> Callable[[str], None] | None:
        """Runs alert_command with the reason appended; no shell and no wait, so it can't block the signer."""
        command = self._service.get("alert_command")
        if not command:
            return None

        def run(reason: str) -> None:
            subprocess.Popen([*command, reason], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return run

    def build_service(self, clock: Callable[[], float] | None = None) -> Any:
        from .audit import Audit
        from .chain import ChainVerifier
        from .signer_service import SignerService
        from .state import SpendState

        state = SpendState(window_seconds=self.window_seconds, journal_path=self.path("journal"))
        audit = Audit(path=self.path("audit"), strict=self.audit_strict)
        verifier = (ChainVerifier(self.rpc_urls, release_block=self.release_block)
                    if self.rpc_urls else None)
        return SignerService(self.load_account(), self.build_policy(), state, audit,
                             verifier=verifier,
                             settlement_grace_seconds=self.settlement_grace_seconds,
                             clock=clock, alert=self.alert())

    @staticmethod
    def _check_keys(where: str, table: dict[str, Any], allowed: set[str],
                    required: set[str]) -> None:
        unknown = set(table) - allowed
        if unknown:
            raise ValueError(f"{where}: unknown key(s) {sorted(unknown)} — "
                             f"a misspelt setting would otherwise be silently ignored. "
                             f"Allowed: {sorted(allowed)}")
        missing = required - set(table)
        if missing:
            raise ValueError(f"{where}: missing required key(s) {sorted(missing)}")

    @staticmethod
    def _int(where: str, value: Any, minimum: int = 0) -> int:
        # bool is an int subclass; `true` must not become an amount of 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{where} must be an integer, got {value!r}")
        if value < minimum:
            raise ValueError(f"{where} must be >= {minimum}, got {value}")
        return value

    @staticmethod
    def _strings(where: str, value: Any) -> None:
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise ValueError(f"{where} must be a list of non-empty strings")

    def _validate_policy(self) -> None:
        p = self._policy
        for key in ("networks", "assets", "schemes", "recipients"):
            if key in p:
                self._strings(f"policy.{key}", p[key])
        if not p["networks"]:
            raise ValueError("policy.networks is empty — that would refuse every payment")
        for key in ("max_per_payment", "total_budget", "recipient_budget", "resource_budget"):
            if key in p:
                self._int(f"policy.{key}", p[key])
        if "max_authorization_window" in p:
            self._int("policy.max_authorization_window", p["max_authorization_window"], 1)
        if "velocity" in p:
            v = p["velocity"]
            if not isinstance(v, dict):
                raise ValueError("[policy.velocity] must be a table")
            self._check_keys("[policy.velocity]", v, _VELOCITY_KEYS, _VELOCITY_KEYS)
            self._int("policy.velocity.max_payments", v["max_payments"])
            self._int("policy.velocity.within_seconds", v["within_seconds"], 1)
        if "price_drift" in p:
            d = p["price_drift"]
            if not isinstance(d, dict):
                raise ValueError("[policy.price_drift] must be a table")
            self._check_keys("[policy.price_drift]", d, _DRIFT_KEYS, {"max_multiple"})
            multiple = d["max_multiple"]
            if isinstance(multiple, bool) or not isinstance(multiple, (int, float)) or multiple <= 0:
                raise ValueError("policy.price_drift.max_multiple must be a positive number")
            if "min_observations" in d:
                self._int("policy.price_drift.min_observations", d["min_observations"], 1)
            if "min_amount_atomic" in d:
                self._int("policy.price_drift.min_amount_atomic", d["min_amount_atomic"])

    def _validate_service(self) -> None:
        s = self._service
        if not s:
            return
        for key in ("key_file", "socket", "journal", "audit"):
            if not isinstance(s[key], str) or not s[key]:
                raise ValueError(f"service.{key} must be a non-empty path string")
        if "rpc_urls" in s:
            from .chain import check_rpc_url
            urls = s["rpc_urls"]
            if not isinstance(urls, dict):
                raise ValueError("service.rpc_urls must map network ids to URLs")
            for network, value in urls.items():
                values = [value] if isinstance(value, str) else value
                if not isinstance(values, list) or not values or not all(
                        isinstance(v, str) and v for v in values):
                    raise ValueError(f"service.rpc_urls.{network} must be a URL or a list of URLs")
                for url in values:
                    check_rpc_url(url)
        for key, minimum in (("settlement_grace_seconds", 0), ("window_seconds", 1),
                             ("reconcile_interval_seconds", 1)):
            if key in s:
                self._int(f"service.{key}", s[key], minimum)
        if "release_block" in s:
            from .chain import RELEASE_BLOCKS
            if s["release_block"] not in RELEASE_BLOCKS:
                raise ValueError(f"service.release_block must be one of {RELEASE_BLOCKS}")
        if "audit_strict" in s and not isinstance(s["audit_strict"], bool):
            raise ValueError("service.audit_strict must be true or false")
        if "alert_command" in s:
            self._strings("service.alert_command", s["alert_command"])
        if "socket_mode" in s:
            try:
                mode = int(str(s["socket_mode"]), 8)
            except ValueError:
                raise ValueError("service.socket_mode must be an octal string like \"660\"")
            if mode & 0o007:
                raise ValueError("service.socket_mode must not grant access to others "
                                 "(anyone who can write the socket can ask for signatures)")

    def _require_service(self, key: str) -> Any:
        if not self._service:
            raise ValueError("this config has no [service] section")
        return self._service[key]


def check_key_file_permissions(path: str | os.PathLike[str]) -> None:
    """A key file the agent's user can read defeats the signer, so group/other access is refused."""
    path = Path(path)
    if not path.exists():
        raise ValueError(f"key file {path} does not exist")
    if os.name == "nt":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ValueError(f"key file {path} has permissions {oct(mode)}; "
                         f"it must be readable only by its owner (chmod 600 {path})")
