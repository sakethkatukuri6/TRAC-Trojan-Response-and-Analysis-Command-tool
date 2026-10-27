"""In-memory fake M7 client for isolated testing."""
from __future__ import annotations

from typing import Any, Dict
from m6_response.m7_client.client_interface import M7ClientInterface


class MemoryM7Client(M7ClientInterface):
    def __init__(self, analysis_store: Dict[str, Dict[str, Any]] = None):
        self.analysis_store: Dict[str, Dict[str, Any]] = analysis_store or {}
        self.submitted_sections: list = []
        self.emitted_events: list = []

    def fetch_analysis(self, analysis_id: str) -> Dict[str, Any]:
        if analysis_id in self.analysis_store:
            return self.analysis_store[analysis_id]
        return {
            "analysis_id": analysis_id,
            "vault_id": analysis_id,
            "verdict": {"label": "malicious", "family_guess": "trojan_generic"},
            "sample": {"sha256": "c" * 64},
            "iocs": {"items": [{"type": "domain", "value": "c2[.]example"}]}
        }

    def submit_section(self, analysis_id: str, section: str, payload: Any) -> Dict[str, Any]:
        self.submitted_sections.append({"analysis_id": analysis_id, "section": section, "payload": payload})
        if analysis_id not in self.analysis_store:
            self.analysis_store[analysis_id] = {"analysis_id": analysis_id}
        self.analysis_store[analysis_id][section] = payload
        return {"status": "stored", "section": section}

    def emit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        self.emitted_events.append(event)
        return {"status": "accepted", "event_id": event.get("event_id")}
