"""Audit: append-only, hash-chained JSONL record of firewall decisions and outcomes."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable

from .state import owner_only

_GENESIS = "0" * 64


class Audit:

    def __init__(self, path: str | os.PathLike[str] | None = None,
                 clock: Callable[[], float] | None = None,
                 strict: bool = True) -> None:
        """strict: a failed write raises RuntimeError, which callers must turn into a denial."""
        self._path = Path(path) if path else None
        self._clock = clock or time.time
        self._strict = strict
        self._lock = threading.RLock()
        self._entries: list[dict[str, Any]] = []
        self._seq = 0
        self._last_hash = _GENESIS
        self._fh = None

        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Resume so a restart extends the chain rather than forking it.
            self._resume()
            self._fh = open(self._path, "a", encoding="utf-8", opener=owner_only)

    def record_decision(self, intent: Any, verdict: Any,
                        reservation_id: str | None = None) -> dict[str, Any]:
        return self._append({
            "event": "decision",
            "allow": bool(verdict["allow"]),
            "rule": verdict["rule"],
            "reason": verdict["reason"],
            "reservation_id": reservation_id,
            "intent": self._serialize(intent),
        })

    def record_settlement(self, reservation_id: str | None, success: bool,
                          transaction: str | None = None,
                          settled_amount_atomic: int | None = None,
                          error: str | None = None) -> dict[str, Any]:
        return self._append({
            "event": "settlement",
            "reservation_id": reservation_id,
            "success": bool(success),
            "transaction": transaction,
            "settled_amount_atomic": settled_amount_atomic,
            "error": error,
        })

    def record_release(self, reservation_id: str | None, reason: str) -> dict[str, Any]:
        return self._append({
            "event": "release",
            "reservation_id": reservation_id,
            "reason": reason,
        })

    def entries(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(e) for e in self._entries)

    def decisions(self, allowed: bool | None = None) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(e) for e in self._entries
                         if e["event"] == "decision"
                         and (allowed is None or e["allow"] is allowed))

    def verify(self) -> tuple[bool, str | None]:
        """Returns (ok, first problem). Tamper-evidence only: a writer can forge a whole new chain."""
        if self._path is None or not self._path.exists():
            return True, None
        prev = _GENESIS
        expected_seq = 1
        with open(self._path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"line {lineno}: not valid JSON"
                if record.get("prev_hash") != prev:
                    return False, f"line {lineno}: chain broken (prev_hash mismatch)"
                if record.get("seq") != expected_seq:
                    return False, f"line {lineno}: sequence gap (expected {expected_seq})"
                stated = record.get("hash")
                if stated != self._hash_of(record):
                    return False, f"line {lineno}: record altered (hash mismatch)"
                prev = stated
                expected_seq += 1
        return True, None

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def _append(self, fields: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            record = {
                "seq": self._seq,
                "ts": self._clock(),
                **fields,
                "prev_hash": self._last_hash,
            }
            record["hash"] = self._hash_of(record)
            self._entries.append(record)
            self._last_hash = record["hash"]
            self._write(record)
            return dict(record)

    @staticmethod
    def _hash_of(record: dict[str, Any]) -> str:
        body = {k: v for k, v in record.items() if k != "hash"}
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()

    def _write(self, record: dict[str, Any]) -> None:
        if self._fh is None:
            return
        try:
            self._fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except (OSError, ValueError) as exc:
            # ValueError is a closed handle; both must honour `strict`.
            if self._strict:
                raise RuntimeError(f"audit write failed: {exc}") from exc

    def _resume(self) -> None:
        if self._path is None or not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._entries.append(record)
                self._seq = record.get("seq", self._seq)
                self._last_hash = record.get("hash", self._last_hash)

    @staticmethod
    def _serialize(value: Any) -> Any:
        if is_dataclass(value) and not isinstance(value, type):
            return json.loads(json.dumps(asdict(value), default=str))
        if isinstance(value, dict):
            return json.loads(json.dumps(value, default=str))
        return str(value)
