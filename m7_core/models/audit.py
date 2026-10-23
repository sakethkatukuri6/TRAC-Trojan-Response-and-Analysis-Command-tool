"""SQLAlchemy model for audit trail."""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, Integer
from m7_core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class AuditLogModel(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(36), nullable=True, index=True)
    action_id = Column(String(36), nullable=True)
    actor = Column(String(64), nullable=False)
    action_type = Column(String(64), nullable=False)
    detail = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
