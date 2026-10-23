"""Action repository for response action tracking."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from m7_core.models.analysis import ActionModel


class ActionRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_action(self, analysis_id: str, data: Dict[str, Any]) -> ActionModel:
        action_id = data["action_id"]
        action = self.db.query(ActionModel).filter(ActionModel.action_id == action_id).first()
        if action:
            action.type = data["type"]
            action.target = data["target"]
            action.mode = data["mode"]
            action.status = data["status"]
            action.playbook = data.get("playbook")
            action.approval = data.get("approval", {"required": False})
            action.executed_at = data.get("executed_at")
            action.audit_ref = data.get("audit_ref")
        else:
            action = ActionModel(
                action_id=action_id,
                analysis_id=analysis_id,
                type=data["type"],
                target=data["target"],
                mode=data["mode"],
                status=data["status"],
                playbook=data.get("playbook"),
                approval=data.get("approval", {"required": False}),
                executed_at=data.get("executed_at"),
                audit_ref=data.get("audit_ref"),
            )
            self.db.add(action)
        self.db.commit()
        self.db.refresh(action)
        return action

    def get_action(self, analysis_id: str, action_id: str) -> Optional[ActionModel]:
        return self.db.query(ActionModel).filter(
            ActionModel.analysis_id == analysis_id,
            ActionModel.action_id == action_id
        ).first()

    def list_actions(self, analysis_id: str) -> List[ActionModel]:
        return self.db.query(ActionModel).filter(ActionModel.analysis_id == analysis_id).all()

    def update_status(
        self,
        analysis_id: str,
        action_id: str,
        status: str,
        approval: Optional[Dict[str, Any]] = None,
        executed_at: Optional[str] = None,
        audit_ref: Optional[str] = None
    ) -> Optional[ActionModel]:
        action = self.get_action(analysis_id, action_id)
        if not action:
            return None
        action.status = status
        if approval:
            action.approval = approval
        if executed_at:
            action.executed_at = executed_at
        if audit_ref:
            action.audit_ref = audit_ref
        self.db.commit()
        self.db.refresh(action)
        return action
