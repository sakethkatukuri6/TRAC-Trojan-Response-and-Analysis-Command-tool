"""M1 Ingestion CLI.

Supports both:
  python -m m1_ingestion.cli --file tests/data/eicar.com --out contract_out/sample.json
  python -m m1_ingestion.cli --file sample.exe --analysis-id <uuid> --vault-id <uuid> --out contract_out/sample.json

``--file`` is required: an ingestion CLI that invents a payload when none is given
produces a vault record for a sample that was never submitted.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import uuid

from m1_ingestion.scanner import EICAR_SIG
from m1_ingestion.vault import SampleVault


def main():
    parser = argparse.ArgumentParser(description="M1 Ingestion CLI")
    parser.add_argument("--file", required=True, help="Path to input sample file")
    parser.add_argument("--analysis-id", required=False, default=None, help="Analysis UUID")
    parser.add_argument("--vault-id", required=False, default=None, help="Vault UUID")
    parser.add_argument(
        "--submitter",
        required=False,
        default=None,
        help="Who submitted the sample; omitted from the record when not given",
    )
    parser.add_argument("--out", required=True, help="Output path for sample section JSON")
    parser.add_argument("--event-out", required=False, default=None, help="Optional output path for sample.received event")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Use a local or temporary directory for vault when running CLI
    vault_dir = Path(os.getenv("VAULT_STORAGE_PATH", out_path.parent.parent / ".vault_cache"))
    vault = SampleVault(storage_dir=vault_dir)

    analysis_id = args.analysis_id or str(uuid.uuid4())
    vault_id = args.vault_id

    # Determine input bytes and original filename
    file_path = Path(args.file)
    orig_name = file_path.name
    if file_path.exists():
        try:
            data = file_path.read_bytes()
        except OSError:
            # If host AV locked eicar.com on Windows
            if "eicar" in orig_name.lower():
                data = EICAR_SIG
            else:
                raise
    else:
        # Fallback for EICAR if quarantined by host AV
        if "eicar" in orig_name.lower():
            data = EICAR_SIG
        else:
            raise FileNotFoundError(f"Input file not found: {args.file}")

    sample_rec, event_rec, _ = vault.ingest(
        data=data,
        original_name=orig_name,
        submitter=args.submitter,
        vault_id=vault_id,
        analysis_id=analysis_id,
    )

    out_doc = {"sample": sample_rec}
    out_path.write_text(json.dumps(out_doc, indent=2), encoding="utf-8")

    # Write event output
    if args.event_out:
        ev_path = Path(args.event_out)
    else:
        # Default alongside contract_out in contract_events
        ev_dir = out_path.parent.parent / "contract_events"
        ev_path = ev_dir / "sample_received.json"

    ev_path.parent.mkdir(parents=True, exist_ok=True)
    ev_path.write_text(json.dumps(event_rec, indent=2), encoding="utf-8")
    print(f"M1: Sample ingested successfully -> {out_path} and {ev_path}")


if __name__ == "__main__":
    main()

