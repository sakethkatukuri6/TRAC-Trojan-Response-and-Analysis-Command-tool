"""M2 Static Analysis CLI.

Usage:
  python -m m2_static.cli --analysis-id <uuid> --out <path>
  python -m m2_static.cli --file <path> --out <path> [--file-type pe] [--analysis-id <uuid>] [--vault-id <uuid>]

Publishes the ``static`` section produced by M2. When run against an analysis ID,
it republishes the section M7 stored for that run. When run against a file, it
executes static analysis directly on the provided bytes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from m2_static.analyzer import analyze_static
from m7_core.contract.loader import get_contract_version
from m7_core.services.analysis_service import load_stored_document

OWNED_SECTIONS = ("static",)


def generate_static_output(doc: dict) -> dict:
    """Return the ``static`` section recorded on the stored document."""
    out = {section: doc[section] for section in OWNED_SECTIONS if section in doc}
    missing = [section for section in OWNED_SECTIONS if section not in out]
    if missing:
        raise LookupError(
            f"Analysis '{doc.get('analysis_id')}' has no static section recorded (missing {missing}); "
            "run the pipeline first."
        )
    return out


def create_event(
    analysis_id: str,
    vault_id: str,
    yara_match_count: int = 0,
) -> Dict[str, Any]:
    """Build the static.done event per contract schema."""
    payload: Dict[str, Any] = {"section": "static"}
    if yara_match_count > 0:
        payload["yara_match_count"] = yara_match_count

    return {
        "event_id": str(uuid.uuid4()),
        "type": "static.done",
        "analysis_id": analysis_id,
        "vault_id": vault_id,
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M2",
        "contract_version": get_contract_version(),
        "payload": payload,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M2 Static Analysis CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--analysis-id", help="Analysis UUID recorded by M7")
    group.add_argument("--file", help="Path to input binary/sample to analyze directly")

    parser.add_argument("--out", required=True, help="Output path for static section JSON")
    parser.add_argument("--event-out", required=False, default=None, help="Optional event output path")
    parser.add_argument("--file-type", default="pe", choices=["pe", "elf", "macho", "script", "doc", "archive", "unknown"], help="File type classifier (default: pe)")
    parser.add_argument("--vault-id", default=None, help="Optional vault ID when running in --file mode")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    event_path = Path(args.event_out) if args.event_out else out_path.parent.parent / "contract_events" / "static_done.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)

    if args.analysis_id:
        try:
            doc = load_stored_document(args.analysis_id)
            out_data = generate_static_output(doc)
            vault_id = str((doc.get("sample") or {}).get("vault_id") or "")
            if not vault_id:
                raise LookupError(
                    f"Analysis '{args.analysis_id}' records no sample.vault_id."
                )
            yara_count = len((doc.get("static") or {}).get("yara_matches") or [])
            event = create_event(args.analysis_id, vault_id, yara_count)
        except LookupError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1
    else:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            return 1

        raw_bytes = file_path.read_bytes()
        static_result = analyze_static(raw_bytes, file_type=args.file_type, filename=file_path.name)
        out_data = {"static": static_result}

        analysis_id = str(uuid.uuid4())
        vault_id = args.vault_id or str(uuid.uuid4())
        yara_count = len(static_result.get("yara_matches") or [])
        event = create_event(analysis_id, vault_id, yara_count)

    out_path.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
    event_path.write_text(json.dumps(event, indent=2), encoding="utf-8")
    print(f"M2: published static analysis to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
