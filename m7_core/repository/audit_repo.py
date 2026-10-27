"""Audit repository."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from m7_core.models.audit import AuditLogModel


class AuditRepository:
    def __init__(self, db: Session):
        self.db = db

    def log(
        self,
        actor: str,
        action_type: str,
        detail: Dict[str, Any],
        analysis_id: Optional[str] = None,
        action_id: Optional[str] = None
    ) -> AuditLogModel:
        entry = AuditLogModel(
            actor=actor,
            action_type=action_type,
            detail=detail,
            analysis_id=analysis_id,
            action_id=action_id
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def list_logs(self, analysis_id: Optional[str] = None, limit: int = 100) -> List[AuditLogModel]:
        q = self.db.query(AuditLogModel)
        if analysis_id:
            q = q.filter(AuditLogModel.analysis_id == analysis_id)
        return q.order_by(AuditLogModel.created_at.desc()).limit(limit).all()
