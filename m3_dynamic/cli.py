"""M3 Dynamic Analysis CLI.

Usage:
  python -m m3_dynamic.cli --analysis-id <uuid> --out <path> [--event-out <path>]

Publishes the ``dynamic`` section recorded for a persisted analysis in M7. Telemetry
is never synthesized: an analysis ID that was not executed in the sandbox or whose
run was skipped reports that real state rather than invented process executions.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from m7_core.contract.loader import get_contract_version
from m7_core.services.analysis_service import load_stored_document

OWNED_SECTIONS = ("dynamic",)


def generate_dynamic_output(doc: dict) -> dict:
    """Return the ``dynamic`` section recorded on the stored document."""
    out = {section: doc[section] for section in OWNED_SECTIONS if section in doc}
    missing = [section for section in OWNED_SECTIONS if section not in out]
    if missing:
        raise LookupError(
            f"Analysis '{doc.get('analysis_id')}' has no dynamic section recorded (missing {missing}); "
            "run the pipeline first."
        )
    return out


def create_event(doc: dict) -> Dict[str, Any]:
    """Build the dynamic.done event per contract schema."""
    vault_id = str((doc.get("sample") or {}).get("vault_id") or "")
    if not vault_id:
        raise LookupError(
            f"Analysis '{doc.get('analysis_id')}' records no sample.vault_id."
        )

    dynamic = doc.get("dynamic") or {}
    sandbox = dynamic.get("sandbox") or {}
    reverted = bool(sandbox.get("reverted", False))

    return {
        "event_id": str(uuid.uuid4()),
        "type": "dynamic.done",
        "analysis_id": doc["analysis_id"],
        "vault_id": vault_id,
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M3",
        "contract_version": get_contract_version(),
        "payload": {
            "section": "dynamic",
            "reverted": reverted,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M3 Dynamic Analysis CLI")
    parser.add_argument("--analysis-id", required=True, help="Analysis UUID recorded by M7")
    parser.add_argument("--out", required=True, help="Output path for dynamic section JSON")
    parser.add_argument("--event-out", required=False, default=None, help="Optional event output path")
    args = parser.parse_args()

    try:
        doc = load_stored_document(args.analysis_id)
        out_data = generate_dynamic_output(doc)
        event = create_event(doc)
    except LookupError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_data, indent=2), encoding="utf-8")

    event_path = Path(args.event_out) if args.event_out else out_path.parent.parent / "contract_events" / "dynamic_done.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_text(json.dumps(event, indent=2), encoding="utf-8")
    print(f"M3: published dynamic analysis for analysis {args.analysis_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
