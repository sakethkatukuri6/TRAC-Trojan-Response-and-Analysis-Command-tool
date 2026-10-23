"""M6 Response Engine CLI.

Usage:
  python -m m6_response.cli --analysis-id <uuid> --vault-id <uuid> --out <path> [--input <fixture.json>] [--mode {dry_run,real}]
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from m6_response.planner.response_planner import ResponsePlanner


def create_response_done_event(
    analysis_id: str,
    vault_id: str,
    action_count: int,
    awaiting_approval_count: int = 0
) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "type": "response.done",
        "analysis_id": analysis_id,
        "vault_id": vault_id,
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M6",
        "contract_version": "1.0.0",
        "payload": {
            "section": "response_actions",
            "action_count": action_count,
            "awaiting_approval": awaiting_approval_count
        }
    }


def main():
    parser = argparse.ArgumentParser(description="M6 Response Engine CLI")
    parser.add_argument("--analysis-id", required=True, help="Analysis UUID")
    parser.add_argument("--vault-id", required=False, default=None, help="Vault UUID")
    parser.add_argument("--out", required=True, help="Output JSON path")
    parser.add_argument("--input", required=False, default=None, help="Optional path to analysis fixture")
    parser.add_argument("--mode", choices=["dry_run", "real"], default="dry_run", help="Execution mode (default: dry_run)")
    args = parser.parse_args()

    analysis_id = args.analysis_id
    vault_id = args.vault_id or analysis_id

    # Load analysis document from fixture or fallback
    if args.input and Path(args.input).exists():
        with open(args.input, "r", encoding="utf-8") as f:
            doc = json.load(f)
    else:
        example_path = Path("contract/examples/valid_synthetic_trojan_record.json")
        if example_path.exists():
            with open(example_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        else:
            doc = {
                "analysis_id": analysis_id,
                "vault_id": vault_id,
                "verdict": {"label": "malicious", "family_guess": "trojan_generic"},
                "sample": {"sha256": "c" * 64},
                "iocs": {"items": [{"type": "domain", "value": "c2[.]example"}]}
            }

    doc["analysis_id"] = analysis_id
    doc["vault_id"] = vault_id

    planner = ResponsePlanner(mode=args.mode)
    actions = planner.plan_response(doc)

    out_data = {
        "response_actions": actions
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)

    awaiting_count = sum(1 for a in actions if a.get("status") == "awaiting_approval")
    event = create_response_done_event(analysis_id, vault_id, len(actions), awaiting_count)

    event_path = out_path.parent.parent / "contract_events" / "response_done.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    with open(event_path, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=2)


if __name__ == "__main__":
    main()
