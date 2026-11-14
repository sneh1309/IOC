"""Hash-chained, append-only audit log (chain of custody for every action Aletheia takes).

Each JSON line contains the SHA-256 of the previous entry, so any edit, deletion or
re-ordering of an entry breaks the chain and is detected by `aletheia verify`.
"""

from __future__ import annotations

import getpass
import json
import os
import socket
import threading
from typing import Any, Optional

from aletheia.core.util import canonical_json, sha256_bytes, utc_now

GENESIS = "0" * 64


def _actor() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


class AuditLog:
    def __init__(self, path: str, case_id: str):
        self.path = path
        self.case_id = case_id
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        if os.path.exists(path):
            # Resume an existing chain (used by the remediation stage, which appends
            # to its own log but may reference the analysis chain head).
            for entry in self.read(path):
                self._seq = entry["seq"]
                self._prev = entry["hash"]

    def record(self, action: str, details: Optional[dict] = None, actor: Optional[str] = None) -> dict:
        with self._lock:
            self._seq += 1
            entry: dict[str, Any] = {
                "seq": self._seq,
                "timestamp_utc": utc_now(),
                "case_id": self.case_id,
                "actor": actor or _actor(),
                "action": action,
                "details": details or {},
                "prev_hash": self._prev,
            }
            entry["hash"] = sha256_bytes(canonical_json(entry))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._prev = entry["hash"]
            return entry

    @property
    def head(self) -> str:
        return self._prev

    @staticmethod
    def read(path: str) -> list:
        out = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    @staticmethod
    def verify(path: str) -> tuple:
        """Return (ok, problems, entry_count, head_hash)."""
        problems = []
        prev = GENESIS
        entries = AuditLog.read(path)
        for i, entry in enumerate(entries, start=1):
            claimed = entry.get("hash")
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("seq") != i:
                problems.append(f"entry {i}: sequence number {entry.get('seq')} out of order")
            if entry.get("prev_hash") != prev:
                problems.append(f"entry {i}: prev_hash does not link to entry {i - 1}")
            if sha256_bytes(canonical_json(body)) != claimed:
                problems.append(f"entry {i}: content hash mismatch (entry altered)")
            prev = claimed
        return (not problems, problems, len(entries), prev)
