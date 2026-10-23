"""Tamper-evident audit chain value object for M6."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid


@dataclass(frozen=True)
class AuditEntry:
    entry_id: str
    prev_hash: str
    timestamp: str
    actor: str
    action_type: str
    detail: Dict[str, Any]
    entry_hash: str

    @classmethod
    def create(cls, prev_hash: str, actor: str, action_type: str, detail: Dict[str, Any]) -> AuditEntry:
        entry_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()
        serialized = json.dumps({
            "entry_id": entry_id,
            "prev_hash": prev_hash,
            "timestamp": ts,
            "actor": actor,
            "action_type": action_type,
            "detail": detail
        }, sort_keys=True)
        h = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return cls(
            entry_id=entry_id,
            prev_hash=prev_hash,
            timestamp=ts,
            actor=actor,
            action_type=action_type,
            detail=detail,
            entry_hash=h
        )

    def verify_hash(self) -> bool:
        serialized = json.dumps({
            "entry_id": self.entry_id,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action_type": self.action_type,
            "detail": self.detail
        }, sort_keys=True)
        expected = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return self.entry_hash == expected


class AuditChain:
    GENESIS_HASH = "0" * 64

    def __init__(self):
        self.entries: List[AuditEntry] = []

    def append(self, actor: str, action_type: str, detail: Dict[str, Any]) -> AuditEntry:
        prev_hash = self.entries[-1].entry_hash if self.entries else self.GENESIS_HASH
        entry = AuditEntry.create(prev_hash, actor, action_type, detail)
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        if not self.entries:
            return True
        prev = self.GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != prev:
                return False
            if not entry.verify_hash():
                return False
            prev = entry.entry_hash
        return True

    def to_list(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self.entries]
