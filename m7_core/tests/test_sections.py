"""Test section writing, ownership enforcement, schema validation, and state conflict."""
import uuid


def test_valid_m6_section_write(client, m6_token):
    aid = str(uuid.uuid4())
    payload = [
        {
            "action_id": str(uuid.uuid4()),
            "type": "block_hash",
            "target": "c" * 64,
            "mode": "dry_run",
            "status": "proposed",
            "playbook": "trojan_generic",
            "approval": {"required": False}
        }
    ]
    resp = client.put(
        f"/api/v1/analyses/{aid}/sections/response_actions",
        json=payload,
        headers={"Authorization": f"Bearer {m6_token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "stored"


def test_cross_owner_rejection(client, m5_token):
    aid = str(uuid.uuid4())
    payload = [
        {
            "action_id": str(uuid.uuid4()),
            "type": "block_hash",
            "target": "c" * 64,
            "mode": "dry_run",
            "status": "proposed",
            "playbook": "trojan_generic",
            "approval": {"required": False}
        }
    ]
    resp = client.put(
        f"/api/v1/analyses/{aid}/sections/response_actions",
        json=payload,
        headers={"Authorization": f"Bearer {m5_token}"}
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["detail"]["code"] == "SECTION_NOT_OWNED"


def test_pipeline_write_rejection(client, m6_token):
    aid = str(uuid.uuid4())
    payload = {"status": "complete"}
    resp = client.put(
        f"/api/v1/analyses/{aid}/sections/pipeline",
        json=payload,
        headers={"Authorization": f"Bearer {m6_token}"}
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "SECTION_NOT_OWNED"


def test_invalid_action_payload_rejection(client, m6_token):
    aid = str(uuid.uuid4())
    # Malformed action: missing required 'target', 'mode', 'status'
    payload = [{"action_id": str(uuid.uuid4()), "type": "block_hash"}]
    resp = client.put(
        f"/api/v1/analyses/{aid}/sections/response_actions",
        json=payload,
        headers={"Authorization": f"Bearer {m6_token}"}
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["detail"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert len(data["detail"]["errors"]) > 0


def test_final_state_conflict_rejection(client, m6_token, db_session):
    from m7_core.repository.analysis_repo import AnalysisRepository
    aid = str(uuid.uuid4())
    repo = AnalysisRepository(db_session)
    repo.create(aid, aid, "b" * 64, status="complete")

    payload = []
    resp = client.put(
        f"/api/v1/analyses/{aid}/sections/response_actions",
        json=payload,
        headers={"Authorization": f"Bearer {m6_token}"}
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "STATE_CONFLICT"
