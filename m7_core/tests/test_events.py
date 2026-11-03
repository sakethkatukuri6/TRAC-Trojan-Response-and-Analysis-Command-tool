"""Test event processor, state machine transitions, idempotency, retries, and ordering."""
import pytest
import uuid
from m7_core.contract.loader import get_contract_version, get_state_machine
from m7_core.services.event_processor import (
    ContractConfigError,
    EventProcessor,
    EventStateConflictError,
    EventProducerMismatchError,
)
from m7_core.repository.analysis_repo import AnalysisRepository


def _stage_failed(aid: str, vid: str, attempt: int, producer: str = "M6") -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "type": "stage.failed",
        "analysis_id": aid,
        "vault_id": vid,
        "emitted_at": "2026-10-22T09:00:00Z",
        "producer": producer,
        "contract_version": get_contract_version(),
        "attempt": attempt,
        "payload": {
            "stage": "response",
            "code": "CONN_TIMEOUT",
            "retryable": True,
            "message": "Temporary connection timeout",
        },
    }


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


def test_retry_boundary_is_the_contract_max_attempts(db_session):
    """The last attempt that still retries is the number state_machine.yaml publishes.

    A literal 3 in the processor and a literal 3 in this test would agree with each
    other while both disagreed with the contract.
    """
    max_attempts = get_state_machine()["failure"]["retry"]["max_attempts"]
    assert max_attempts >= 2, "contract declares no meaningful retry budget"

    repo = AnalysisRepository(db_session)
    processor = EventProcessor(db_session)
    aid, vid = str(uuid.uuid4()), str(uuid.uuid4())
    repo.create(aid, vid, "e" * 64, status="response")

    r_last_retry = processor.process_event(_stage_failed(aid, vid, max_attempts - 1), caller_module="M6")
    assert r_last_retry["status"] == "retry_scheduled"

    r_exhausted = processor.process_event(_stage_failed(aid, vid, max_attempts), caller_module="M6")
    assert r_exhausted["status"] == get_state_machine()["failure"]["on_exhausted"]
    assert repo.get_by_id(aid).pipeline_status == get_state_machine()["failure"]["on_exhausted"]


@pytest.mark.parametrize("state", get_state_machine()["failure"]["from_any"])
def test_stage_failed_is_allowed_from_every_state_the_contract_lists(db_session, state):
    repo = AnalysisRepository(db_session)
    processor = EventProcessor(db_session)
    aid, vid = str(uuid.uuid4()), str(uuid.uuid4())
    repo.create(aid, vid, "e" * 64, status=state)

    result = processor.process_event(_stage_failed(aid, vid, 1), caller_module="M6")
    assert result["status"] == "retry_scheduled"


def test_stage_failed_is_rejected_outside_the_contract_failure_states(db_session):
    """'received' is not in failure.from_any, so a failure there is an ordering bug."""
    repo = AnalysisRepository(db_session)
    processor = EventProcessor(db_session)
    aid, vid = str(uuid.uuid4()), str(uuid.uuid4())
    repo.create(aid, vid, "e" * 64, status="received")

    with pytest.raises(EventStateConflictError):
        processor.process_event(_stage_failed(aid, vid, 1), caller_module="M6")


@pytest.mark.parametrize(
    "failure_cfg",
    [
        {},
        {"from_any": ["static"]},                                  # no retry budget
        {"from_any": ["static"], "retry": {"max_attempts": 3}},    # no exhausted state
    ],
    ids=["no_failure_block", "no_max_attempts", "no_on_exhausted"],
)
def test_processor_refuses_an_incomplete_failure_policy(db_session, failure_cfg):
    """M7 parks failures somewhere only when the contract says where."""
    processor = EventProcessor(db_session)
    processor.sm = {"transitions": [], "failure": failure_cfg}
    repo = AnalysisRepository(db_session)
    aid, vid = str(uuid.uuid4()), str(uuid.uuid4())
    repo.create(aid, vid, "e" * 64, status="response")

    with pytest.raises(ContractConfigError):
        processor.process_event(_stage_failed(aid, vid, 1), caller_module="M6")

    # Nothing was written: the analysis is still where the failure arrived.
    assert repo.get_by_id(aid).pipeline_status == "response"
