"""Test action approval and rejection routes."""
import uuid
from m7_core.repository.analysis_repo import AnalysisRepository


def test_approval_and_rejection_flow(client, m6_token, analyst_token, db_session):
    aid = str(uuid.uuid4())
    act_id = str(uuid.uuid4())
    act_id2 = str(uuid.uuid4())

    # Pre-create analysis record (as created by M1 intake)
    repo = AnalysisRepository(db_session)
    repo.create(aid, aid, "c" * 64, status="response")

    # 1. Propose actions awaiting approval via M6
    payload = [
        {
            "action_id": act_id,
            "type": "block_domain",
            "target": "c2[.]example",
            "mode": "real",
            "status": "awaiting_approval",
            "playbook": "trojan_generic",
            "approval": {"required": True}
        },
        {
            "action_id": act_id2,
            "type": "isolate_host",
            "target": "host-01",
            "mode": "real",
            "status": "awaiting_approval",
            "playbook": "trojan_generic",
            "approval": {"required": True}
        }
    ]
    r = client.put(
        f"/api/v1/analyses/{aid}/sections/response_actions",
        json=payload,
        headers={"Authorization": f"Bearer {m6_token}"}
    )
    assert r.status_code == 200

    # 2. Reject non-analyst/admin (e.g. module token on approval route)
    r_unauth = client.post(
        f"/api/v1/analyses/{aid}/actions/{act_id}/approve",
        headers={"Authorization": f"Bearer {m6_token}"}
    )
    assert r_unauth.status_code in (401, 403)

    # 3. Approve first action
    r_app = client.post(
        f"/api/v1/analyses/{aid}/actions/{act_id}/approve",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert r_app.status_code == 200
    assert r_app.json()["status"] == "approved"

    # 4. Approving again returns 409 (not awaiting approval)
    r_app2 = client.post(
        f"/api/v1/analyses/{aid}/actions/{act_id}/approve",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert r_app2.status_code == 409

    # 5. Reject second action
    r_rej = client.post(
        f"/api/v1/analyses/{aid}/actions/{act_id2}/reject",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert r_rej.status_code == 200
    assert r_rej.json()["status"] == "rejected"
