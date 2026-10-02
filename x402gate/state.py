"""SpendState: the rolling-window spend ledger, with reservations, journal persistence and price history."""

from __future__ import annotations

import json
import os
import statistics
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

_PENDING = "pending"
_COMMITTED = "committed"

# Err long: expiring a reservation that is still settling undercounts spend.
_DEFAULT_RESERVATION_TIMEOUT = 600


class SpendState:

    def __init__(self, window_seconds: int = 86_400,
                 clock: Callable[[], float] | None = None,
                 journal_path: str | os.PathLike[str] | None = None,
                 default_timeout_seconds: int = _DEFAULT_RESERVATION_TIMEOUT,
                 price_window_seconds: int = 2_592_000,
                 max_price_observations: int = 50,
                 max_price_resources: int = 10_000) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be positive")
        if price_window_seconds <= 0:
            raise ValueError("price_window_seconds must be positive")
        if max_price_observations <= 0:
            raise ValueError("max_price_observations must be positive")
        if max_price_resources <= 0:
            raise ValueError("max_price_resources must be positive")

        self._window = window_seconds
        self._default_timeout = default_timeout_seconds
        self._price_window = price_window_seconds
        self._max_price_observations = max_price_observations
        self._max_price_resources = max_price_resources
        self._prices: dict[str, list[tuple[float, int]]] = {}
        self._new_price_keys = 0
        self._last_price_sweep = 0.0

        # Monotonic-anchored so settimeofday/NTP steps can't move the window.
        self._wall_anchor = time.time()
        self._mono_anchor = time.monotonic()
        self._clock = clock or self._default_clock
        self._last_seen_time = 0.0

        self._lock = threading.RLock()
        self._tx_depth = threading.local()

        self._entries: dict[str, dict[str, Any]] = {}

        self._journal_path = Path(journal_path) if journal_path else None
        self._journal_fh = None
        self._journal_offset = 0
        if self._journal_path is not None:
            self._journal_path.parent.mkdir(parents=True, exist_ok=True)
            # Kept open for the object's lifetime: it is also the flock target.
            self._journal_fh = open(self._journal_path, "a", encoding="utf-8",
                                    opener=owner_only)
            self._sync_from_journal()
            self._sweep_prices()

    @property
    def window_seconds(self) -> int:
        return self._window

    def _default_clock(self) -> float:
        return self._wall_anchor + (time.monotonic() - self._mono_anchor)

    def _now(self) -> float:
        # Clamp backward steps so aged entries never un-expire.
        now = self._clock()
        if now < self._last_seen_time:
            return self._last_seen_time
        self._last_seen_time = now
        return now

    @contextmanager
    def transaction(self) -> Iterator["SpendState"]:
        """Serialize decide+reserve across threads and processes; never await inside it."""
        with self._lock:
            depth = getattr(self._tx_depth, "value", 0)
            self._tx_depth.value = depth + 1
            file_locked = False
            try:
                if depth == 0 and self._journal_fh is not None and fcntl is not None:
                    fcntl.flock(self._journal_fh.fileno(), fcntl.LOCK_EX)
                    file_locked = True
                if depth == 0:
                    self._sync_from_journal()
                yield self
            finally:
                self._tx_depth.value = depth
                if file_locked:
                    fcntl.flock(self._journal_fh.fileno(), fcntl.LOCK_UN)

    def _require_transaction(self) -> None:
        if getattr(self._tx_depth, "value", 0) <= 0:
            raise RuntimeError(
                "reserve() must be called inside SpendState.transaction() — "
                "decide and reserve must be atomic or concurrent payments double-spend"
            )

    def spent_total(self) -> int:
        with self._lock:
            self._prune()
            return sum(e["amount"] for e in self._entries.values())

    def spent_on(self, resource: str) -> int:
        resource = (resource or "").strip()
        with self._lock:
            self._prune()
            return sum(e["amount"] for e in self._entries.values()
                       if (e.get("resource") or "") == resource)

    # Observability only: caller labels are agent-supplied; never build a limit on them.
    def spent_by(self, caller: str) -> int:
        with self._lock:
            self._prune()
            return sum(e["amount"] for e in self._entries.values()
                       if e["caller"] == caller)

    def spent_to(self, recipient: str) -> int:
        recipient = recipient.lower()
        with self._lock:
            self._prune()
            return sum(e["amount"] for e in self._entries.values()
                       if e["recipient"] == recipient)

    def payment_count_total(self, within_seconds: int | None = None) -> int:
        with self._lock:
            self._prune()
            horizon = self._now() - (within_seconds if within_seconds is not None
                                     else self._window)
            return sum(1 for e in self._entries.values() if e["timestamp"] >= horizon)

    def payment_count(self, caller: str, within_seconds: int | None = None) -> int:
        with self._lock:
            self._prune()
            horizon = self._now() - (within_seconds if within_seconds is not None
                                     else self._window)
            return sum(1 for e in self._entries.values()
                       if e["caller"] == caller and e["timestamp"] >= horizon)

    def authorize_payment(self, decide_fn: Callable[[], Any], caller: str,
                          recipient: str, amount_atomic: int,
                          timeout_seconds: int | None = None,
                          network: str = "", asset: str = "",
                          resource: str = "",
                          hold_until_verified: bool = False) -> tuple[Any, str | None]:
        """Decide and reserve atomically. Returns (verdict, reservation_id or None)."""
        with self.transaction():
            verdict = decide_fn()
            if not verdict["allow"]:
                return verdict, None
            reservation_id = self.reserve(
                caller=caller, recipient=recipient, amount_atomic=amount_atomic,
                timeout_seconds=timeout_seconds, network=network, asset=asset,
                resource=resource, hold_until_verified=hold_until_verified,
            )
            return verdict, reservation_id

    def reserve(self, caller: str, recipient: str, amount_atomic: int,
                timeout_seconds: int | None = None,
                network: str = "", asset: str = "", resource: str = "",
                hold_until_verified: bool = False) -> str:
        """Must run inside transaction(). Held reservations are never released on a timer."""
        self._require_transaction()
        if amount_atomic < 0:
            raise ValueError("amount_atomic must be non-negative")
        timeout = int(timeout_seconds if timeout_seconds is not None else self._default_timeout)
        if timeout <= 0:
            raise ValueError("timeout_seconds must be positive")

        now = self._now()
        reservation_id = uuid.uuid4().hex
        entry = {
            "id": reservation_id,
            "timestamp": now,
            "expires_at": now + timeout,
            "caller": caller,
            "recipient": recipient.lower(),
            "amount": int(amount_atomic),
            # Kept separately: price history compares asks, not upto settlements.
            "asked_amount": int(amount_atomic),
            "network": network,
            "asset": asset,
            "resource": resource or "",
            "status": _PENDING,
            "verify": bool(hold_until_verified),
        }
        self._entries[reservation_id] = entry
        self._write_journal({"op": "reserve", **entry})
        return reservation_id

    def reserved_amount(self, reservation_id: str) -> int:
        with self._lock:
            entry = self._entries.get(reservation_id)
            if entry is None:
                raise KeyError(f"no reservation {reservation_id!r}")
            return int(entry["amount"])

    def awaiting_verification(self) -> tuple[dict[str, Any], ...]:
        """Held reservations past expiry; they keep counting until the chain decides."""
        with self._lock:
            self._prune()
            now = self._now()
            return tuple(dict(e) for e in self._entries.values()
                         if e["status"] == _PENDING and e.get("verify")
                         and e.get("expires_at", 0) <= now)

    def commit(self, reservation_id: str, settled_amount_atomic: int | None = None,
               payer: str | None = None, transaction: str | None = None) -> None:
        with self.transaction():
            entry = self._entries.get(reservation_id)
            if entry is None:
                raise KeyError(f"no reservation {reservation_id!r}")
            if entry["status"] == _COMMITTED:
                raise ValueError(f"reservation {reservation_id!r} already committed")
            if settled_amount_atomic is not None:
                if settled_amount_atomic < 0:
                    raise ValueError("settled amount must be non-negative")
                if settled_amount_atomic > entry["amount"]:
                    raise ValueError(
                        f"settled {settled_amount_atomic} exceeds reserved {entry['amount']}"
                    )
                entry["amount"] = int(settled_amount_atomic)
            entry["status"] = _COMMITTED
            if payer:
                entry["payer"] = payer.lower()
            if transaction:
                entry["transaction"] = transaction
            self._write_journal({"op": "commit", "id": reservation_id,
                                 "amount": entry["amount"],
                                 "payer": entry.get("payer"),
                                 "transaction": entry.get("transaction")})
            # Only accepted prices enter history, so refused asks can't walk the median up.
            if entry.get("resource"):
                self.record_price(entry["resource"], entry.get("network", ""),
                                  entry.get("asset", ""),
                                  int(entry.get("asked_amount", entry["amount"])))

    def release(self, reservation_id: str) -> None:
        with self.transaction():
            entry = self._entries.get(reservation_id)
            if entry is None:
                raise KeyError(f"no reservation {reservation_id!r}")
            if entry["status"] == _COMMITTED:
                raise ValueError(f"reservation {reservation_id!r} is committed; cannot release")
            del self._entries[reservation_id]
            self._write_journal({"op": "release", "id": reservation_id})

    def bind_reference(self, reservation_id: str, reference: str,
                       valid_before: int | None = None) -> None:
        """Journaled so a settlement arriving after a restart still matches its reservation."""
        with self.transaction():
            entry = self._entries.get(reservation_id)
            if entry is None:
                raise KeyError(f"no reservation {reservation_id!r}")
            entry["ref"] = reference
            if valid_before is not None:
                entry["valid_before"] = int(valid_before)
            self._write_journal({"op": "bind", "id": reservation_id, "ref": reference,
                                 "valid_before": entry.get("valid_before")})

    def find_reservation_by_ref(self, reference: str) -> str | None:
        with self._lock:
            self._prune()
            return next((k for k, e in self._entries.items() if e.get("ref") == reference),
                        None)

    def reservation_status(self, reservation_id: str) -> str | None:
        with self._lock:
            self._prune()
            entry = self._entries.get(reservation_id)
            return entry["status"] if entry is not None else None

    def has_settled_transaction(self, transaction: str) -> bool:
        if not transaction:
            return False
        with self._lock:
            self._prune()
            return any(e.get("transaction") == transaction for e in self._entries.values())

    def record_unreserved_settlement(self, caller: str, recipient: str, amount_atomic: int,
                                     network: str = "", asset: str = "", resource: str = "",
                                     payer: str | None = None, transaction: str | None = None,
                                     asked_amount_atomic: int | None = None) -> str:
        """Count spend that settled with no live reservation (late, or after a restart)."""
        if amount_atomic < 0:
            raise ValueError("amount_atomic must be non-negative")
        with self.transaction():
            now = self._now()
            entry_id = uuid.uuid4().hex
            asked = int(asked_amount_atomic if asked_amount_atomic is not None else amount_atomic)
            entry = {
                "id": entry_id, "timestamp": now, "expires_at": now,
                "caller": caller, "recipient": recipient.lower(),
                "amount": int(amount_atomic), "asked_amount": asked,
                "network": network, "asset": asset, "resource": resource or "",
                "status": _COMMITTED,
                "payer": payer.lower() if payer else None,
                "transaction": transaction or None,
            }
            self._entries[entry_id] = entry
            self._write_journal({"op": "settled", **entry})
            if resource:
                self.record_price(resource, network, asset, asked)
            return entry_id

    @staticmethod
    def price_key(resource: str, network: str, asset: str) -> str:
        return f"{(resource or '').strip()}|{(network or '').lower()}|{(asset or '').lower()}"

    def record_price(self, resource: str, network: str, asset: str,
                     asked_amount_atomic: int) -> None:
        if not resource:
            return
        # A free call is not a price; a 0 median would lock the endpoint's paid calls.
        if int(asked_amount_atomic) <= 0:
            return
        key = self.price_key(resource, network, asset)
        with self._lock:
            if key not in self._prices:
                # A hostile server can rotate URLs; keep the key set bounded.
                self._new_price_keys += 1
                if (self._new_price_keys >= 256 or len(self._prices) >= self._max_price_resources
                        or self._now() - self._last_price_sweep >= 3_600):
                    self._sweep_prices()
            series = self._prices.setdefault(key, [])
            series.append((self._now(), int(asked_amount_atomic)))
            if len(series) > self._max_price_observations:
                del series[: len(series) - self._max_price_observations]
            self._write_journal({"op": "price", "key": key,
                                 "ts": self._now(), "amount": int(asked_amount_atomic)})

    def price_observation_count(self, resource: str, network: str, asset: str) -> int:
        with self._lock:
            return len(self._live_prices(self.price_key(resource, network, asset)))

    def price_baseline(self, resource: str, network: str, asset: str,
                       min_observations: int = 1) -> int | None:
        """Median accepted price; None means "cannot judge", not "fine"."""
        with self._lock:
            amounts = [amount for _, amount in
                       self._live_prices(self.price_key(resource, network, asset))]
            if len(amounts) < max(1, min_observations):
                return None
            return int(statistics.median(amounts))

    def _sweep_prices(self) -> None:
        horizon = self._now() - self._price_window
        for key in [k for k, s in self._prices.items() if not s or s[-1][0] < horizon]:
            del self._prices[key]
        excess = len(self._prices) - self._max_price_resources + 1
        if excess > 0:
            excess = max(excess, self._max_price_resources // 10)
            for key in sorted(self._prices, key=lambda k: self._prices[k][-1][0])[:excess]:
                del self._prices[key]
        self._new_price_keys = 0
        self._last_price_sweep = self._now()

    def _live_prices(self, key: str) -> list[tuple[float, int]]:
        horizon = self._now() - self._price_window
        series = self._prices.get(key, [])
        live = [(ts, amount) for ts, amount in series if ts >= horizon]
        if len(live) != len(series):
            self._prices[key] = live
        return live

    def outstanding(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            self._prune()
            return tuple(dict(e) for e in self._entries.values()
                         if e["status"] == _PENDING)

    def _prune(self) -> None:
        now = self._now()
        horizon = now - self._window
        for key in [k for k, e in self._entries.items()
                    if e["status"] == _PENDING and not e.get("verify")
                    and e.get("expires_at", 0) <= now]:
            del self._entries[key]
            self._write_journal({"op": "expire", "id": key})
        for key in [k for k, e in self._entries.items()
                    if e["status"] == _COMMITTED and e["timestamp"] < horizon]:
            del self._entries[key]

    def _write_journal(self, record: dict[str, Any]) -> None:
        if self._journal_fh is None:
            return
        self._journal_fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._journal_fh.flush()
        # fsync: a budget that doesn't survive a power cut isn't a budget.
        os.fsync(self._journal_fh.fileno())
        self._journal_offset = self._journal_path.stat().st_size  # type: ignore[union-attr]

    def _sync_from_journal(self) -> None:
        if self._journal_path is None or not self._journal_path.exists():
            return
        with open(self._journal_path, "r", encoding="utf-8") as rf:
            rf.seek(self._journal_offset)
            for line in rf:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    op = record["op"]
                    if op == "reserve":
                        entry = {k: v for k, v in record.items() if k != "op"}
                        self._entries[entry["id"]] = entry
                        self._last_seen_time = max(self._last_seen_time,
                                                   float(entry["timestamp"]))
                    elif op == "commit":
                        entry = self._entries.get(record["id"])
                        if entry is not None:
                            entry["amount"] = record["amount"]
                            entry["status"] = _COMMITTED
                            if record.get("payer"):
                                entry["payer"] = record["payer"]
                            if record.get("transaction"):
                                entry["transaction"] = record["transaction"]
                    elif op == "bind":
                        entry = self._entries.get(record["id"])
                        if entry is not None:
                            entry["ref"] = record["ref"]
                            if record.get("valid_before") is not None:
                                entry["valid_before"] = int(record["valid_before"])
                    elif op == "settled":
                        entry = {k: v for k, v in record.items() if k != "op"}
                        self._entries[entry["id"]] = entry
                        self._last_seen_time = max(self._last_seen_time,
                                                   float(entry["timestamp"]))
                    elif op in ("release", "expire"):
                        self._entries.pop(record["id"], None)
                    elif op == "price":
                        series = self._prices.setdefault(record["key"], [])
                        series.append((float(record["ts"]), int(record["amount"])))
                        if len(series) > self._max_price_observations:
                            del series[: len(series) - self._max_price_observations]
                # A torn final write must not block startup; skip what can't be parsed.
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
            self._journal_offset = rf.tell()

    def close(self) -> None:
        if self._journal_fh is not None:
            self._journal_fh.close()
            self._journal_fh = None


def owner_only(path: str, flags: int) -> int:
    """File opener: refuses a symlinked path and leaves the file mode 0600, even if it pre-existed."""
    fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    return fd
