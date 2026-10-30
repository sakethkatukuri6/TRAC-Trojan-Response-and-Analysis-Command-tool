"""M6 Response Engine CLI.

Usage:
  python -m m6_response.cli --analysis-id <uuid> --out <path>
  python -m m6_response.cli --input <analysis.json> --out <path>

Plans response actions for an analysis M7 has persisted, or for a document the operator
names explicitly with --input. Nothing is substituted when neither is available:
planning against a synthetic sample would emit response actions for a host that was
never infected.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid

from m6_response.planner.response_planner import ResponsePlanner
from m7_core.services.analysis_service import load_stored_document


def load_document(analysis_id: str | None, input_path: str | None) -> dict:
    """Read the analysis to plan against, from M7 or from an explicit file."""
    if input_path:
        path = Path(input_path)
        if not path.exists():
            raise LookupError(f"Analysis document '{input_path}' does not exist.")
        return json.loads(path.read_text(encoding="utf-8"))
    return load_stored_document(str(analysis_id))


def create_response_done_event(doc: dict, actions: list) -> dict:
    """Build the response.done event from the plan this run actually produced."""
    analysis_id = str(doc.get("analysis_id") or "")
    vault_id = str((doc.get("sample") or {}).get("vault_id") or "")
    if not analysis_id or not vault_id:
        raise LookupError(
            "This analysis document carries no analysis_id/sample.vault_id, so the "
            "response plan cannot be attributed to an analysis or a sample."
        )
    awaiting_count = sum(1 for a in actions if a.get("status") == "awaiting_approval")
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
            "action_count": len(actions),
            "awaiting_approval": awaiting_count
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M6 Response Engine CLI")
    parser.add_argument("--analysis-id", help="Analysis UUID recorded by M7")
    parser.add_argument("--input", help="Explicit analysis document to plan against")
    parser.add_argument("--out", required=True, help="Output JSON path")
    parser.add_argument("--event-out", required=False, default=None, help="Optional event output path")
    parser.add_argument("--mode", choices=["dry_run", "real"], default="dry_run", help="Execution mode (default: dry_run)")
    args = parser.parse_args()

    if bool(args.analysis_id) == bool(args.input):
        print("[!] Give exactly one of --analysis-id (a persisted analysis) or --input (a document).", file=sys.stderr)
        return 2

    try:
        doc = load_document(args.analysis_id, args.input)
    except (LookupError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    actions = ResponsePlanner(mode=args.mode).plan_response(doc)
    try:
        event = create_response_done_event(doc, actions)
    except LookupError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"response_actions": actions}, indent=2), encoding="utf-8")

    event_path = (
        Path(args.event_out)
        if args.event_out
        else out_path.parent.parent / "contract_events" / "response_done.json"
    )
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_text(json.dumps(event, indent=2), encoding="utf-8")
    print(f"M6: planned {len(actions)} response action(s) for analysis {event['analysis_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
