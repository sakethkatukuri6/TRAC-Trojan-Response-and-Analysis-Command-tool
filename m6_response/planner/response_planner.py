"""Deterministic Response Planner for M6.

Consumes a complete analysis document and produces contract-valid response_actions list.
Defaults every action to dry_run. When real mode is configured, destructive actions
(quarantine, isolate_host, block_ip, block_domain) require approval.required=true
and status=awaiting_approval.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid
import yaml

from m6_response.planner.approval_gate import DESTRUCTIVE_TYPES

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"


def load_playbook(name: str) -> Dict[str, Any]:
    path = PLAYBOOKS_DIR / f"{name}.yaml"
    if not path.exists():
        path = PLAYBOOKS_DIR / "trojan_generic.yaml"
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _resolve_target(target_rule: Dict[str, Any], doc: Dict[str, Any]) -> Optional[str]:
    """Resolve an action target from observed data only.

    Returns ``None`` when the document carries no such indicator; a target is
    never invented, because a containment action against a fabricated domain,
    IP or host would be an untruthful instruction.
    """
    if "target_fixed" in target_rule:
        return target_rule["target_fixed"]

    src = target_rule.get("target_from", "")
    if src == "sample.sha256":
        return doc.get("sample", {}).get("sha256")

    if src == "iocs.domain":
        iocs = doc.get("iocs", {}).get("items", [])
        for item in iocs:
            if item.get("type") == "domain":
                return item.get("value")
        return None

    if src == "iocs.ip":
        iocs = doc.get("iocs", {}).get("items", [])
        for item in iocs:
            if item.get("type") == "ip":
                return item.get("value")
        return None

    if src.startswith("dynamic."):
        return doc.get("dynamic", {}).get("sandbox", {}).get("guest_os")

    return None


class ResponsePlanner:
    def __init__(self, mode: str = "dry_run"):
        """Default every action to dry_run per build guide requirements."""
        self.mode = mode

    def select_playbook_name(self, doc: Dict[str, Any]) -> Optional[str]:
        verdict = doc.get("verdict", {})
        label = verdict.get("label", "unknown")
        family = str(verdict.get("family_guess", "")).lower()

        if label == "benign":
            return None

        if "rat" in family:
            return "rat"
        if "stealer" in family:
            return "stealer"

        if label == "malicious":
            return "trojan_generic"
        if label == "suspicious":
            return "suspicious_review"

        return "trojan_generic"

    def plan_response(self, doc: Dict[str, Any], override_mode: Optional[str] = None) -> List[Dict[str, Any]]:
        playbook_name = self.select_playbook_name(doc)
        if not playbook_name:
            return []

        playbook = load_playbook(playbook_name)
        analysis_id = doc.get("analysis_id", str(uuid.uuid4()))
        actions_out: List[Dict[str, Any]] = []

        effective_mode = override_mode or self.mode
        rules = playbook.get("actions", [])

        for idx, rule in enumerate(rules):
            action_type = rule["type"]
            target = _resolve_target(rule, doc)
            if not target:
                # No observed indicator backs this action, so none is proposed.
                continue
            mode = effective_mode
            status = "proposed"

            # Deterministic UUID5 based on analysis_id and action index/type/target/mode
            seed = f"{analysis_id}:{idx}:{action_type}:{target}:{mode}"
            action_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))

            # Approval requirements:
            # Planning a real quarantine, isolate_host, block_ip, or block_domain action
            # requires approval.required=true and status=awaiting_approval
            if mode == "real" and action_type in DESTRUCTIVE_TYPES:
                approval = {"required": True}
                status = "awaiting_approval"
            else:
                approval = {"required": False}
                status = "proposed"

            action_dict: Dict[str, Any] = {
                "action_id": action_id,
                "type": action_type,
                "target": target,
                "mode": mode,
                "status": status,
                "playbook": playbook_name,
                "approval": approval
            }

            actions_out.append(action_dict)

        return actions_out
