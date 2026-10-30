"""Test action approval and rejection routes."""
import uuid
from m7_core.api.auth import USER_SECRET, create_jwt_token
from m7_core.models.audit import AuditLogModel
from m7_core.repository.analysis_repo import AnalysisRepository


def _propose_awaiting_action(client, db_session, m6_token, action_type="block_domain"):
    """Seed an analysis holding one action that needs an analyst decision."""
    aid = str(uuid.uuid4())
    act_id = str(uuid.uuid4())
    AnalysisRepository(db_session).create(aid, aid, "c" * 64, status="response")
    res = client.put(
        f"/api/v1/analyses/{aid}/sections/response_actions",
        json=[
            {
                "action_id": act_id,
                "type": action_type,
                "target": "c2[.]example" if action_type == "block_domain" else "host-01",
                "mode": "real",
                "status": "awaiting_approval",
                "playbook": "trojan_generic",
                "approval": {"required": True},
            }
        ],
        headers={"Authorization": f"Bearer {m6_token}"},
    )
    assert res.status_code == 200, res.text
    return aid, act_id


def test_approval_is_attributed_to_the_token_subject(client, db_session, m6_token, analyst_token):
    """The audit chain names whoever approved, taken from the token that was presented."""
    aid, act_id = _propose_awaiting_action(client, db_session, m6_token, "isolate_host")

    res = client.post(
        f"/api/v1/analyses/{aid}/actions/{act_id}/approve",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 200
    assert res.json()["approved_by"] == "analyst_user"

    entry = (
        db_session.query(AuditLogModel)
        .filter_by(analysis_id=aid, action_type="approve_action")
        .one()
    )
    assert entry.actor == "analyst_user"


def test_rejection_is_attributed_to_the_token_subject(client, db_session, m6_token, admin_token):
    aid, act_id = _propose_awaiting_action(client, db_session, m6_token)

    res = client.post(
        f"/api/v1/analyses/{aid}/actions/{act_id}/reject",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "rejected"

    entry = (
        db_session.query(AuditLogModel)
        .filter_by(analysis_id=aid, action_type="reject_action")
        .one()
    )
    assert entry.actor == "admin_user"


def test_approval_without_a_subject_is_refused(client, db_session, m6_token):
    """A token that identifies nobody cannot be recorded as having approved an action."""
    anonymous = create_jwt_token({"type": "user", "role": "analyst"}, USER_SECRET)
    aid, act_id = _propose_awaiting_action(client, db_session, m6_token, "isolate_host")

    res = client.post(
        f"/api/v1/analyses/{aid}/actions/{act_id}/approve",
        headers={"Authorization": f"Bearer {anonymous}"},
    )
    assert res.status_code == 401
    assert (
        db_session.query(AuditLogModel).filter_by(analysis_id=aid, action_type="approve_action").count()
        == 0
    )


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
