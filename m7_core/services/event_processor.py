"""Pure event processor and state machine engine for M7 Core.

Enforces:
- Schema validation via events.schema.json
- Caller module authorization (producer match)
- Strict state machine transitions per state_machine.yaml (rejects out-of-order events)
- Idempotency by event_id
- Retry logic and dead_letter transitions
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from m7_core.contract.loader import get_state_machine, validate_event
from m7_core.repository.analysis_repo import AnalysisRepository
from m7_core.repository.event_repo import EventRepository
from m7_core.repository.audit_repo import AuditRepository


class EventValidationError(Exception):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("; ".join(errors))


class EventProducerMismatchError(Exception):
    """Raised when the event producer does not match the authenticated caller module."""
    pass


class EventStateConflictError(Exception):
    """Raised when an event is received out-of-order or from an invalid pipeline state."""
    pass


class EventProcessor:
    def __init__(self, db: Session):
        self.db = db
        self.analysis_repo = AnalysisRepository(db)
        self.event_repo = EventRepository(db)
        self.audit_repo = AuditRepository(db)
        self.sm = get_state_machine()

    def process_event(self, event: Dict[str, Any], caller_module: Optional[str] = None) -> Dict[str, Any]:
        # 1. Schema validate event
        errs = validate_event(event)
        if errs:
            raise EventValidationError(errs)

        event_id = event["event_id"]
        event_type = event["type"]
        analysis_id = event["analysis_id"]
        vault_id = event["vault_id"]
        producer = event["producer"]
        payload = event.get("payload", {})
        emitted_at = event["emitted_at"]

        # 2. Check caller authentication matches producer
        if caller_module is not None and caller_module != producer:
            raise EventProducerMismatchError(
                f"Authenticated module '{caller_module}' cannot emit event for producer '{producer}'"
            )

        # 3. Idempotency check: duplicate event_id
        existing = self.event_repo.get_by_event_id(event_id)
        if existing:
            return {
                "status": "duplicate",
                "event_id": event_id,
                "message": "Event already processed"
            }

        # 4. Check analysis existence and current pipeline state
        analysis = self.analysis_repo.get_by_id(analysis_id)
        if not analysis:
            if event_type == "sample.received":
                # Initial intake event creates the analysis in received state
                analysis = self.analysis_repo.create(
                    analysis_id=analysis_id,
                    vault_id=vault_id,
                    sha256=payload.get("sha256", "0" * 64),
                    status="received"
                )
            else:
                raise EventStateConflictError(
                    f"Cannot process event '{event_type}' for non-existent analysis '{analysis_id}'"
                )

        current_state = analysis.pipeline_status

        # 5. Handle stage.failed event
        if event_type == "stage.failed":
            failure_cfg = self.sm.get("failure", {})
            from_any = failure_cfg.get("from_any", ["static", "dynamic", "iocs", "scoring", "response", "report"])
            if current_state not in from_any:
                raise EventStateConflictError(
                    f"Failure event 'stage.failed' not allowed from state '{current_state}'"
                )

            retryable = payload.get("retryable", False)
            attempt = event.get("attempt", 1)

            if retryable and attempt < 3:
                self.event_repo.record_event(
                    event_id=event_id,
                    event_type=event_type,
                    analysis_id=analysis_id,
                    vault_id=vault_id,
                    producer=producer,
                    payload=payload,
                    emitted_at=emitted_at,
                    status="retry_scheduled",
                    attempt=attempt
                )
                return {
                    "status": "retry_scheduled",
                    "attempt": attempt + 1,
                    "event_id": event_id
                }
            else:
                self.analysis_repo.update_pipeline(analysis_id=analysis_id, status="dead_letter")
                self.event_repo.record_event(
                    event_id=event_id,
                    event_type=event_type,
                    analysis_id=analysis_id,
                    vault_id=vault_id,
                    producer=producer,
                    payload=payload,
                    emitted_at=emitted_at,
                    status="dead_letter",
                    attempt=attempt
                )
                return {
                    "status": "dead_letter",
                    "event_id": event_id
                }

        # 6. Look up state machine transition
        transitions = self.sm.get("transitions", [])
        matched = None
        for tr in transitions:
            if tr["event"] == event_type:
                matched = tr
                break

        if not matched:
            raise ValueError(f"Unknown event type: {event_type}")

        expected_from = matched["from"]
        next_to = matched["to"]

        # 7. Strict state machine check (prevent out-of-order transitions)
        if current_state != expected_from:
            if current_state == next_to:
                # Already at target state - idempotent success
                self.event_repo.record_event(
                    event_id=event_id,
                    event_type=event_type,
                    analysis_id=analysis_id,
                    vault_id=vault_id,
                    producer=producer,
                    payload=payload,
                    emitted_at=emitted_at,
                    status="processed"
                )
                return {"status": "ok", "state": next_to, "idempotent": True}
            # Out of order! Reject with conflict
            raise EventStateConflictError(
                f"Event '{event_type}' not allowed from state '{current_state}' (expected '{expected_from}')"
            )

        # 8. Record completed stage
        stage_map = {
            "sample.received": "ingest",
            "static.done": "static",
            "dynamic.done": "dynamic",
            "iocs.done": "iocs",
            "scoring.done": "scoring",
            "response.done": "response",
            "report.done": "report"
        }
        completed_stage = stage_map.get(event_type)
        updated_stages = {}
        if completed_stage:
            updated_stages[completed_stage] = "done"

        # 9. Apply state transition
        self.analysis_repo.update_pipeline(
            analysis_id=analysis_id,
            status=next_to,
            stages=updated_stages
        )

        self.event_repo.record_event(
            event_id=event_id,
            event_type=event_type,
            analysis_id=analysis_id,
            vault_id=vault_id,
            producer=producer,
            payload=payload,
            emitted_at=emitted_at,
            status="processed"
        )

        self.audit_repo.log(
            actor=producer,
            action_type="state_transition",
            detail={"event": event_type, "from": current_state, "to": next_to},
            analysis_id=analysis_id
        )

        return {
            "status": "transitioned",
            "from_state": current_state,
            "to_state": next_to,
            "event_id": event_id
        }
