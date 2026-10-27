"""Fake in-memory connectors for M6.

Guarantees no real network, firewall, host, notification, or external API side effects occur.
"""
from __future__ import annotations

from typing import Any, Dict, List
from m6_response.planner.approval_gate import assert_approved


class FakeConnector:
    def __init__(self):
        self.executed_actions: List[Dict[str, Any]] = []

    def execute_action(self, action: Dict[str, Any], recorded_approvals: Dict[str, Any] = None) -> Dict[str, Any]:
        # Enforce approval gate before simulated execution
        assert_approved(action, recorded_approvals)

        record = {
            "action_id": action.get("action_id"),
            "type": action.get("type"),
            "target": action.get("target"),
            "mode": action.get("mode"),
            "executed": True,
            "simulated": True
        }
        self.executed_actions.append(record)
        return record

    def clear(self):
        self.executed_actions.clear()
