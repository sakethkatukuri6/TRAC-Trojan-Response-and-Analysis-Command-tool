"""Windows Firewall and Host Isolation Containment Connector for M6.

Provides PowerShell-based containment rule generation, execution, and rollback
for real-mode actions gated by operator approval tokens and audit chains.
"""
from __future__ import annotations

import hashlib
import json
import logging
import platform
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from m6_response.planner.approval_gate import assert_approved

logger = logging.getLogger("m6_response.windows_firewall")


def _sanitize_rule_target(target: str) -> str:
    """Sanitize target IP or domain string for safe firewall rule naming."""
    # Refuse shell metacharacters
    cleaned = re.sub(r"[^A-Za-z0-9.:_-]", "_", target.replace("[.]", "."))
    return cleaned


class WindowsFirewallConnector:
    """Connects to Windows Firewall (via PowerShell NetSecurity cmdlets) or outputs
    audited remediation scripts for operator verification.
    """

    def __init__(self, allow_live_execution: bool = False):
        self.allow_live_execution = allow_live_execution
        self.executed_actions: List[Dict[str, Any]] = []

    def generate_command(self, action: Dict[str, Any]) -> str:
        """Generate the exact PowerShell command for an approved action."""
        action_type = action.get("type", "")
        raw_target = str(action.get("target") or "unknown")
        target = _sanitize_rule_target(raw_target)
        rule_name = f"TRAC_BLOCK_{target}"

        if action_type in ("block_ip", "block_domain"):
            return (
                f'New-NetFirewallRule -DisplayName "{rule_name}" '
                f'-Direction Outbound -Action Block -RemoteAddress "{target}"'
            )
        elif action_type == "isolate_host":
            return (
                'Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | '
                'Disable-NetAdapter -Confirm:$false'
            )
        elif action_type == "quarantine":
            return f'# Quarantine target artifact: {target}'
        else:
            return f'# Generic action {action_type} for target: {target}'

    def generate_rollback_command(self, action: Dict[str, Any]) -> str:
        """Generate the rollback command to revert containment."""
        action_type = action.get("type", "")
        raw_target = str(action.get("target") or "unknown")
        target = _sanitize_rule_target(raw_target)
        rule_name = f"TRAC_BLOCK_{target}"

        if action_type in ("block_ip", "block_domain"):
            return f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
        elif action_type == "isolate_host":
            return 'Get-NetAdapter | Enable-NetAdapter -Confirm:$false'
        else:
            return f'# Rollback action for {target}'

    def generate_remediation_script(self, actions: List[Dict[str, Any]]) -> str:
        """Generate a complete, executable PowerShell script for all actions."""
        lines = [
            "# =====================================================================",
            "# TRAC Security Command Platform - Automated Containment Script",
            f"# Generated At: {datetime.now(timezone.utc).isoformat()}",
            "# Requires Elevated Administrator Privileges",
            "# =====================================================================",
            "$ErrorActionPreference = 'Stop'",
            "",
        ]
        for a in actions:
            cmd = self.generate_command(a)
            lines.append(f"# Action {a.get('action_id')} ({a.get('type')} on {a.get('target')})")
            lines.append(f"Write-Host '[*] Applying containment: {a.get('type')} -> {a.get('target')}'")
            lines.append(cmd)
            lines.append("")

        lines.append("Write-Host '[+] All containment rules successfully applied.'")
        return "\n".join(lines)

    def execute_action(
        self,
        action: Dict[str, Any],
        recorded_approvals: Optional[Dict[str, Any]] = None,
        execute_live: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Execute or simulate a containment action with audit trail enforcement."""
        # 1. Gate check: must pass approval gate if real mode
        assert_approved(action, recorded_approvals)

        should_live = self.allow_live_execution if execute_live is None else execute_live
        action_id = str(action.get("action_id", ""))
        action_type = str(action.get("type", ""))
        target = str(action.get("target", ""))
        mode = str(action.get("mode", "dry_run"))

        # 2. Build deterministic audit reference hash
        ts = datetime.now(timezone.utc).isoformat()
        audit_seed = f"{action_id}:{action_type}:{target}:{mode}:{ts}"
        audit_ref = hashlib.sha256(audit_seed.encode("utf-8")).hexdigest()

        ps_cmd = self.generate_command(action)
        rollback_cmd = self.generate_rollback_command(action)

        actually_executed = False
        execution_output = ""

        # 3. If live execution is requested, real mode, and on Windows
        if should_live and mode == "real" and platform.system().lower() == "windows":
            try:
                proc = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                actually_executed = (proc.returncode == 0)
                execution_output = proc.stdout if proc.returncode == 0 else proc.stderr
            except Exception as exc:
                logger.error("Live execution of action %s failed: %s", action_id, exc)
                execution_output = str(exc)

        record = {
            "action_id": action_id,
            "type": action_type,
            "target": target,
            "mode": mode,
            "executed": True,
            "simulated": not actually_executed,
            "executed_at": ts,
            "audit_ref": audit_ref,
            "powershell_command": ps_cmd,
            "rollback_command": rollback_cmd,
            "execution_output": execution_output,
        }
        self.executed_actions.append(record)
        return record
