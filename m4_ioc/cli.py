"""M4 IOC Extraction CLI.

Usage:
  python -m m4_ioc.cli --analysis-id <uuid> --out <path>

Publishes the ``iocs`` section M4 extracted for a persisted analysis. Indicators are
reportable only if an extraction actually found them: an analysis id that was never
run is an error, not a template of domains, mutexes and beacons.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid
from datetime import datetime, timezone

from m7_core.contract.loader import get_contract_version
from m7_core.services.analysis_service import load_stored_document

OWNED_SECTIONS = ("iocs",)


def generate_iocs_output(doc: dict) -> dict:
    """Return the ``iocs`` section recorded on the stored document."""
    out = {section: doc[section] for section in OWNED_SECTIONS if section in doc}
    missing = [section for section in OWNED_SECTIONS if section not in out]
    if missing:
        raise LookupError(
            f"Analysis '{doc.get('analysis_id')}' has no IOC section recorded (missing {missing}); "
            "run the pipeline first. Indicators are never invented here."
        )
    return out


def create_event(doc: dict) -> dict:
    """Build the iocs.done event from the indicators M4 actually extracted."""
    vault_id = str((doc.get("sample") or {}).get("vault_id") or "")
    if not vault_id:
        raise LookupError(
            f"Analysis '{doc.get('analysis_id')}' records no sample.vault_id, "
            "so no IOC event can be attributed to a sample."
        )
    return {
        "event_id": str(uuid.uuid4()),
        "type": "iocs.done",
        "analysis_id": doc["analysis_id"],
        "vault_id": vault_id,
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M4",
        "contract_version": get_contract_version(),
        "payload": {
            "section": "iocs",
            "ioc_count": len(doc["iocs"].get("items") or [])
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M4 IOC Extraction CLI")
    parser.add_argument("--analysis-id", required=True, help="Analysis UUID recorded by M7")
    parser.add_argument("--out", required=True, help="Output path for IOC section JSON")
    parser.add_argument("--event-out", required=False, default=None, help="Optional event output path")
    args = parser.parse_args()

    try:
        doc = load_stored_document(args.analysis_id)
        out_data = generate_iocs_output(doc)
        event = create_event(doc)
    except LookupError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_data, indent=2), encoding="utf-8")

    event_path = Path(args.event_out) if args.event_out else out_path.parent.parent / "contract_events" / "iocs_done.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_text(json.dumps(event, indent=2), encoding="utf-8")
    print(f"M4: published {sorted(out_data)} for analysis {args.analysis_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
