"""Approval Gate for M6 Executor.

Refuses execution of destructive actions in real mode unless explicit recorded approval exists.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

DESTRUCTIVE_TYPES = {"quarantine", "isolate_host", "block_ip", "block_domain"}


class UnapprovedActionRefusalError(RuntimeError):
    """Raised when an unapproved real-mode destructive action is attempted."""
    pass


def assert_approved(action: Dict[str, Any], recorded_approvals: Optional[Dict[str, Any]] = None) -> None:
    action_type = action.get("type")
    mode = action.get("mode")

    if mode == "real" and action_type in DESTRUCTIVE_TYPES:
        action_id = action.get("action_id")
        approval = action.get("approval", {})
        is_approved = (
            action.get("status") == "approved"
            and bool(approval.get("approved_by"))
            and bool(approval.get("approved_at"))
        )
        if recorded_approvals and action_id in recorded_approvals:
            is_approved = True

        if not is_approved:
            raise UnapprovedActionRefusalError(
                f"Action '{action_id}' of type '{action_type}' in real mode cannot be executed without recorded approval"
            )
