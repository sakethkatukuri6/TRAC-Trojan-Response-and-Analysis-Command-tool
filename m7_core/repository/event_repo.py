"""Event repository for idempotency and event logging."""
from __future__ import annotations

from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from m7_core.models.events import EventRecordModel


class EventRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_event_id(self, event_id: str) -> Optional[EventRecordModel]:
        return self.db.query(EventRecordModel).filter(EventRecordModel.event_id == event_id).first()

    def record_event(
        self,
        event_id: str,
        event_type: str,
        analysis_id: str,
        vault_id: str,
        producer: str,
        payload: Dict[str, Any],
        emitted_at: str,
        status: str = "processed",
        attempt: int = 1
    ) -> EventRecordModel:
        record = EventRecordModel(
            event_id=event_id,
            event_type=event_type,
            analysis_id=analysis_id,
            vault_id=vault_id,
            producer=producer,
            payload=payload,
            emitted_at=emitted_at,
            status=status,
            attempt=attempt
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def update_event(self, event_id: str, status: str, attempt: Optional[int] = None) -> Optional[EventRecordModel]:
        rec = self.get_by_event_id(event_id)
        if not rec:
            return None
        rec.status = status
        if attempt is not None:
            rec.attempt = attempt
        self.db.commit()
        self.db.refresh(rec)
        return rec
