"""Approval and Rejection service for response actions."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from m7_core.repository.action_repo import ActionRepository
from m7_core.repository.audit_repo import AuditRepository


class ActionNotFoundError(Exception):
    pass


class ActionStateConflictError(Exception):
    pass


class ApprovalService:
    def __init__(self, db: Session):
        self.db = db
        self.action_repo = ActionRepository(db)
        self.audit_repo = AuditRepository(db)

    def approve_action(self, analysis_id: str, action_id: str, actor: str) -> Dict[str, Any]:
        action = self.action_repo.get_action(analysis_id, action_id)
        if not action:
            raise ActionNotFoundError(f"Action {action_id} not found")
        if action.status != "awaiting_approval":
            raise ActionStateConflictError(f"Action is not awaiting approval (current status: {action.status})")

        now_iso = datetime.now(timezone.utc).isoformat()
        approval_data = dict(action.approval or {})
        approval_data["required"] = True
        approval_data["approved_by"] = actor
        approval_data["approved_at"] = now_iso

        self.action_repo.update_status(
            analysis_id=analysis_id,
            action_id=action_id,
            status="approved",
            approval=approval_data
        )

        self.audit_repo.log(
            actor=actor,
            action_type="approve_action",
            detail={"action_id": action_id, "approved_at": now_iso},
            analysis_id=analysis_id,
            action_id=action_id
        )

        return {
            "status": "approved",
            "action_id": action_id,
            "approved_by": actor,
            "approved_at": now_iso
        }

    def reject_action(self, analysis_id: str, action_id: str, actor: str) -> Dict[str, Any]:
        action = self.action_repo.get_action(analysis_id, action_id)
        if not action:
            raise ActionNotFoundError(f"Action {action_id} not found")
        if action.status != "awaiting_approval":
            raise ActionStateConflictError(f"Action is not awaiting approval (current status: {action.status})")

        self.action_repo.update_status(
            analysis_id=analysis_id,
            action_id=action_id,
            status="rejected"
        )

        self.audit_repo.log(
            actor=actor,
            action_type="reject_action",
            detail={"action_id": action_id},
            analysis_id=analysis_id,
            action_id=action_id
        )

        return {
            "status": "rejected",
            "action_id": action_id
        }
