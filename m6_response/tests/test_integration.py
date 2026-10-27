"""Phase 4 Integration test: M6 -> M7 end-to-end communication."""
import uuid
from fastapi.testclient import TestClient

from m7_core.api.app import app
from m7_core.api.auth import create_module_token, create_user_token
from m7_core.repository.analysis_repo import AnalysisRepository
from m7_core.database import SessionLocal, init_db
from m6_response.planner.response_planner import ResponsePlanner


def test_m6_to_m7_integration_flow(trojan_fixture):
    init_db()
    with TestClient(app) as client:
        m6_token = create_module_token("M6")
        analyst_token = create_user_token("analyst1", "analyst")

        aid = str(uuid.uuid4())
        vid = str(uuid.uuid4())
        trojan_fixture["analysis_id"] = aid
        trojan_fixture["vault_id"] = vid

        # 1. Setup analysis in M7 DB in response state
        db = SessionLocal()
        repo = AnalysisRepository(db)
        repo.create(aid, vid, trojan_fixture["sample"]["sha256"], status="response")
        db.close()

        # 2. Test M7 rejects unauthenticated /events call
        event_unauth = {
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
        res_unauth = client.post("/api/v1/events", json=event_unauth)
        assert res_unauth.status_code == 401

        # 3. Test M7 rejects out-of-order event on an analysis in 'received' state
        aid_received = str(uuid.uuid4())
        db = SessionLocal()
        repo = AnalysisRepository(db)
        repo.create(aid_received, vid, "f" * 64, status="received")
        db.close()

        res_ooo = client.post(
            "/api/v1/events",
            json={
                "event_id": str(uuid.uuid4()),
                "type": "response.done",
                "analysis_id": aid_received,
                "vault_id": vid,
                "emitted_at": "2026-10-22T09:00:00Z",
                "producer": "M6",
                "contract_version": "1.0.0",
                "payload": {"section": "response_actions", "action_count": 1}
            },
            headers={"Authorization": f"Bearer {m6_token}"}
        )
        assert res_ooo.status_code == 409

        # 4. M6 response planner generates actions with real mode for approval testing
        planner = ResponsePlanner(mode="real")
        actions = planner.plan_response(trojan_fixture)
        assert len(actions) > 0

        # 5. M6 writes response_actions to M7 via PUT sections
        put_resp = client.put(
            f"/api/v1/analyses/{aid}/sections/response_actions",
            json=actions,
            headers={"Authorization": f"Bearer {m6_token}"}
        )
        assert put_resp.status_code == 200

        # 6. High-risk action stays awaiting approval
        awaiting_action = next(a for a in actions if a["status"] == "awaiting_approval")
        act_id = awaiting_action["action_id"]

        # 7. Analyst approves high-risk action in M7
        appr_resp = client.post(
            f"/api/v1/analyses/{aid}/actions/{act_id}/approve",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        assert appr_resp.status_code == 200
        assert appr_resp.json()["status"] == "approved"

        # 8. M6 emits response.done event to M7 with valid module auth
        event_id = str(uuid.uuid4())
        event = {
            "event_id": event_id,
            "type": "response.done",
            "analysis_id": aid,
            "vault_id": vid,
            "emitted_at": "2026-10-22T09:00:00Z",
            "producer": "M6",
            "contract_version": "1.0.0",
            "payload": {
                "section": "response_actions",
                "action_count": len(actions),
                "awaiting_approval": 1
            }
        }
        ev_resp = client.post(
            "/api/v1/events",
            json=event,
            headers={"Authorization": f"Bearer {m6_token}"}
        )
        assert ev_resp.status_code == 200
        assert ev_resp.json()["status"] == "transitioned"
        assert ev_resp.json()["to_state"] == "report"

        # 9. Check M7 document is now in 'report' status
        doc_resp = client.get(f"/api/v1/analyses/{aid}", headers={"Authorization": f"Bearer {analyst_token}"})
        assert doc_resp.status_code == 200
        doc = doc_resp.json()
        assert doc["pipeline"]["status"] == "report"
        assert doc["pipeline"]["stages"]["response"] == "done"
        assert "response_actions" in doc

        # 10. Duplicate event is idempotent
        ev_dup_resp = client.post(
            "/api/v1/events",
            json=event,
            headers={"Authorization": f"Bearer {m6_token}"}
        )
        assert ev_dup_resp.status_code == 200
        assert ev_dup_resp.json()["status"] == "duplicate"
