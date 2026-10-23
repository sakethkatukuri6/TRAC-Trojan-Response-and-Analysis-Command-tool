"""Audit sink interface delegating durable persistence to M7."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from m6_response.audit.audit_chain import AuditEntry


class AuditSink(ABC):
    @abstractmethod
    def record_audit(self, entry: AuditEntry) -> None:
        pass


class MemoryAuditSink(AuditSink):
    def __init__(self):
        self.recorded: List[AuditEntry] = []

    def record_audit(self, entry: AuditEntry) -> None:
        self.recorded.append(entry)
