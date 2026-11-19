"""Tests for Windows Firewall and Host Isolation Containment Connector."""
from datetime import datetime, timezone
import pytest

from m6_response.connectors.windows_firewall import WindowsFirewallConnector, _sanitize_rule_target
from m6_response.planner.approval_gate import UnapprovedActionRefusalError


def test_target_sanitization_removes_defanging_brackets():
    assert _sanitize_rule_target("192[.]0[.]2[.]1") == "192.0.2.1"
    assert _sanitize_rule_target("bad[.]example[.]com") == "bad.example.com"
    assert _sanitize_rule_target("bad;whoami") == "bad_whoami"


def test_command_generation_block_ip():
    connector = WindowsFirewallConnector()
    action = {
        "action_id": "act-1",
        "type": "block_ip",
        "target": "198.51.100.4",
        "mode": "dry_run",
    }
    cmd = connector.generate_command(action)
    assert 'New-NetFirewallRule -DisplayName "TRAC_BLOCK_198.51.100.4"' in cmd
    assert '-RemoteAddress "198.51.100.4"' in cmd

    rollback = connector.generate_rollback_command(action)
    assert 'Remove-NetFirewallRule -DisplayName "TRAC_BLOCK_198.51.100.4"' in rollback


def test_command_generation_isolate_host():
    connector = WindowsFirewallConnector()
    action = {
        "action_id": "act-2",
        "type": "isolate_host",
        "target": "WORKSTATION-01",
        "mode": "dry_run",
    }
    cmd = connector.generate_command(action)
    assert "Disable-NetAdapter" in cmd

    rollback = connector.generate_rollback_command(action)
    assert "Enable-NetAdapter" in rollback


def test_remediation_script_generation():
    connector = WindowsFirewallConnector()
    actions = [
        {"action_id": "a-1", "type": "block_ip", "target": "10.0.0.5", "mode": "dry_run"},
        {"action_id": "a-2", "type": "block_domain", "target": "c2[.]evil[.]com", "mode": "dry_run"},
    ]
    script = connector.generate_remediation_script(actions)
    assert "TRAC Security Command Platform" in script
    assert "TRAC_BLOCK_10.0.0.5" in script
    assert "TRAC_BLOCK_c2.evil.com" in script


def test_execute_action_refuses_unapproved_real_mode():
    connector = WindowsFirewallConnector()
    unapproved_real_action = {
        "action_id": "act-real-1",
        "type": "block_ip",
        "target": "192.0.2.99",
        "mode": "real",
        "status": "awaiting_approval",
    }
    with pytest.raises(UnapprovedActionRefusalError):
        connector.execute_action(unapproved_real_action)


def test_execute_action_succeeds_with_valid_approval():
    connector = WindowsFirewallConnector()
    approved_action = {
        "action_id": "act-real-2",
        "type": "block_ip",
        "target": "192.0.2.100",
        "mode": "real",
        "status": "approved",
        "approval": {
            "required": True,
            "approved_by": "sec_operator_1",
            "approved_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    rec = connector.execute_action(approved_action, execute_live=False)
    assert rec["executed"] is True
    assert rec["simulated"] is True
    assert rec["action_id"] == "act-real-2"
    assert bool(rec["audit_ref"])
    assert "New-NetFirewallRule" in rec["powershell_command"]
    assert len(connector.executed_actions) == 1
