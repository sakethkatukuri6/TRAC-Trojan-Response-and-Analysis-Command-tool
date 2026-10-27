"""SQLAlchemy model for event idempotency and pipeline tracking."""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, Integer
from m7_core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class EventRecordModel(Base):
    __tablename__ = "event_records"

    event_id = Column(String(36), primary_key=True)
    event_type = Column(String(64), nullable=False, index=True)
    analysis_id = Column(String(36), nullable=False, index=True)
    vault_id = Column(String(36), nullable=False)
    producer = Column(String(16), nullable=False)
    attempt = Column(Integer, default=1, nullable=False)
    status = Column(String(32), default="processed", nullable=False)
    payload = Column(JSON, nullable=False)
    emitted_at = Column(String(64), nullable=False)
    received_at = Column(DateTime, default=utc_now, nullable=False)
