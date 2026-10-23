"""Test M6 response planner across different malware verdicts and playbooks."""
from m6_response.planner.response_planner import ResponsePlanner


def test_malicious_fixture_planning_defaults_to_dry_run(trojan_fixture):
    """Default every action to dry_run per build guide requirements."""
    planner = ResponsePlanner()
    actions = planner.plan_response(trojan_fixture)
    assert len(actions) > 0

    types = [a["type"] for a in actions]
    assert "block_hash" in types
    assert "block_domain" in types

    # By default, EVERY action is dry_run and proposed
    for a in actions:
        assert a["mode"] == "dry_run"
        assert a["status"] == "proposed"
        assert a["approval"]["required"] is False


def test_real_mode_planning_requires_approval(trojan_fixture):
    """Planning in real mode requires approval for destructive actions."""
    planner = ResponsePlanner(mode="real")
    actions = planner.plan_response(trojan_fixture)

    block_dom = next(a for a in actions if a["type"] == "block_domain")
    assert block_dom["mode"] == "real"
    assert block_dom["approval"]["required"] is True
    assert block_dom["status"] == "awaiting_approval"


def test_benign_fixture_planning(benign_fixture):
    planner = ResponsePlanner()
    actions = planner.plan_response(benign_fixture)
    assert actions == []


def test_suspicious_planning():
    planner = ResponsePlanner()
    doc = {
        "analysis_id": "00000003-0000-4000-8000-000000000003",
        "verdict": {"label": "suspicious"},
        "score": {"value": 45}
    }
    actions = planner.plan_response(doc)
    types = [a["type"] for a in actions]
    assert "open_ticket" in types
    assert "notify" in types
    for a in actions:
        assert a["mode"] == "dry_run"


def test_rat_family_planning():
    planner = ResponsePlanner(mode="real")
    doc = {
        "analysis_id": "00000003-0000-4000-8000-000000000003",
        "verdict": {"label": "malicious", "family_guess": "njrat"},
        "sample": {"sha256": "c" * 64},
        "dynamic": {"sandbox": {"guest_os": "win10-x64"}},
        "iocs": {"items": [{"type": "domain", "value": "c2[.]example"}]}
    }
    actions = planner.plan_response(doc)
    types = [a["type"] for a in actions]
    assert "isolate_host" in types
    iso = next(a for a in actions if a["type"] == "isolate_host")
    assert iso["mode"] == "real"
    assert iso["approval"]["required"] is True
    assert iso["status"] == "awaiting_approval"


def test_stealer_family_planning():
    planner = ResponsePlanner()
    doc = {
        "analysis_id": "00000003-0000-4000-8000-000000000003",
        "verdict": {"label": "malicious", "family_guess": "redline_stealer"},
        "sample": {"sha256": "c" * 64},
        "iocs": {"items": [{"type": "domain", "value": "c2[.]example"}]}
    }
    actions = planner.plan_response(doc)
    types = [a["type"] for a in actions]
    assert "notify" in types


def test_deterministic_idempotency(trojan_fixture):
    planner = ResponsePlanner()
    actions1 = planner.plan_response(trojan_fixture)
    actions2 = planner.plan_response(trojan_fixture)
    assert [a["action_id"] for a in actions1] == [a["action_id"] for a in actions2]
