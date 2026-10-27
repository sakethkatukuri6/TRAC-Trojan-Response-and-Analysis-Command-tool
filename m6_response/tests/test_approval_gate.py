"""Test approval gate and executor safety."""
import pytest
from m6_response.planner.approval_gate import assert_approved, UnapprovedActionRefusalError
from m6_response.connectors.fake_connectors import FakeConnector


def test_destructive_real_action_refused_without_approval():
    unapproved_action = {
        "action_id": "0000001f-0000-4000-8000-00000000001f",
        "type": "isolate_host",
        "target": "endpoint-1",
        "mode": "real",
        "status": "awaiting_approval",
        "approval": {"required": True}
    }
    with pytest.raises(UnapprovedActionRefusalError):
        assert_approved(unapproved_action)

    connector = FakeConnector()
    with pytest.raises(UnapprovedActionRefusalError):
        connector.execute_action(unapproved_action)


def test_approved_action_passes_gate():
    approved_action = {
        "action_id": "0000001f-0000-4000-8000-00000000001f",
        "type": "isolate_host",
        "target": "endpoint-1",
        "mode": "real",
        "status": "approved",
        "approval": {"required": True, "approved_by": "analyst1", "approved_at": "2026-10-22T09:00:00Z"}
    }
    # Should not raise
    assert_approved(approved_action)

    connector = FakeConnector()
    res = connector.execute_action(approved_action)
    assert res["executed"] is True
    assert res["simulated"] is True


def test_dry_run_action_passes_gate():
    dry_run_action = {
        "action_id": "0000001e-0000-4000-8000-00000000001e",
        "type": "isolate_host",
        "target": "endpoint-1",
        "mode": "dry_run",
        "status": "proposed",
        "approval": {"required": False}
    }
    assert_approved(dry_run_action)
