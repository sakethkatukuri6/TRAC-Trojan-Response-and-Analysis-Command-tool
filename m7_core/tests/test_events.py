"""Test event processor, state machine transitions, idempotency, retries, and ordering."""
import pytest
import uuid
from m7_core.services.event_processor import EventProcessor, EventStateConflictError, EventProducerMismatchError
from m7_core.repository.analysis_repo import AnalysisRepository


def test_response_done_advances_state(db_session):
    repo = AnalysisRepository(db_session)
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    # Start in response state
    analysis = repo.create(aid, vid, "c" * 64, status="response")
    assert analysis.pipeline_status == "response"

    processor = EventProcessor(db_session)
    ev_id = str(uuid.uuid4())
    ev = {
        "event_id": ev_id,
        "type": "response.done",
        "analysis_id": aid,
        "vault_id": vid,
        "emitted_at": "2026-10-22T09:00:00Z",
        "producer": "M6",
        "contract_version": "1.0.0",
        "payload": {
            "section": "response_actions",
            "action_count": 2,
            "awaiting_approval": 1
        }
    }

    res = processor.process_event(ev, caller_module="M6")
    assert res["status"] == "transitioned"
    assert res["to_state"] == "report"

    # Check DB state
    updated = repo.get_by_id(aid)
    assert updated.pipeline_status == "report"
    assert updated.pipeline_stages.get("response") == "done"


def test_out_of_order_event_rejected(db_session):
    """Critical: response.done cannot advance an analysis in 'received' state to 'report'."""
    repo = AnalysisRepository(db_session)
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    repo.create(aid, vid, "c" * 64, status="received")

    processor = EventProcessor(db_session)
    ev = {
        "event_id": str(uuid.uuid4()),
        "type": "response.done",
        "analysis_id": aid,
        "vault_id": vid,
        "emitted_at": "2026-10-22T09:00:00Z",
        "producer": "M6",
        "contract_version": "1.0.0",
        "payload": {
            "section": "response_actions",
            "action_count": 1
        }
    }

    with pytest.raises(EventStateConflictError):
        processor.process_event(ev, caller_module="M6")

    # State should remain unchanged
    analysis = repo.get_by_id(aid)
    assert analysis.pipeline_status == "received"


def test_producer_mismatch_rejected(db_session):
    """Caller M5 cannot emit event with producer M6."""
    repo = AnalysisRepository(db_session)
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    repo.create(aid, vid, "c" * 64, status="response")

    processor = EventProcessor(db_session)
    ev = {
        "event_id": str(uuid.uuid4()),
        "type": "response.done",
        "analysis_id": aid,
        "vault_id": vid,
        "emitted_at": "2026-10-22T09:00:00Z",
        "producer": "M6",
        "contract_version": "1.0.0",
        "payload": {
            "section": "response_actions",
            "action_count": 1
        }
    }

    with pytest.raises(EventProducerMismatchError):
        processor.process_event(ev, caller_module="M5")


def test_duplicate_event_idempotency(db_session):
    repo = AnalysisRepository(db_session)
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    repo.create(aid, vid, "d" * 64, status="response")

    processor = EventProcessor(db_session)
    ev_id = str(uuid.uuid4())
    ev = {
        "event_id": ev_id,
        "type": "response.done",
        "analysis_id": aid,
        "vault_id": vid,
        "emitted_at": "2026-10-22T09:00:00Z",
        "producer": "M6",
        "contract_version": "1.0.0",
        "payload": {
            "section": "response_actions",
            "action_count": 1
        }
    }

    r1 = processor.process_event(ev, caller_module="M6")
    assert r1["status"] == "transitioned"

    # Second dispatch with identical event_id
    r2 = processor.process_event(ev, caller_module="M6")
    assert r2["status"] == "duplicate"


def test_retry_exhaustion_moves_to_dead_letter(db_session):
    repo = AnalysisRepository(db_session)
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    repo.create(aid, vid, "e" * 64, status="response")

    processor = EventProcessor(db_session)

    # Attempt 1: retryable -> retry_scheduled
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "type": "stage.failed",
        "analysis_id": aid,
        "vault_id": vid,
        "emitted_at": "2026-10-22T09:00:00Z",
        "producer": "M6",
        "contract_version": "1.0.0",
        "attempt": 1,
        "payload": {
            "stage": "response",
            "code": "CONN_TIMEOUT",
            "retryable": True,
            "message": "Temporary connection timeout"
        }
    }
    r1 = processor.process_event(ev1, caller_module="M6")
    assert r1["status"] == "retry_scheduled"

    # Attempt 3: exhausted -> dead_letter
    ev3 = {
        "event_id": str(uuid.uuid4()),
        "type": "stage.failed",
        "analysis_id": aid,
        "vault_id": vid,
        "emitted_at": "2026-10-22T09:05:00Z",
        "producer": "M6",
        "contract_version": "1.0.0",
        "attempt": 3,
        "payload": {
            "stage": "response",
            "code": "CONN_TIMEOUT",
            "retryable": True,
            "message": "Max attempts reached"
        }
    }
    r3 = processor.process_event(ev3, caller_module="M6")
    assert r3["status"] == "dead_letter"

    updated = repo.get_by_id(aid)
    assert updated.pipeline_status == "dead_letter"
