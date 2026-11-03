"""M7 Core Command Line Interface.

Usage:
  python -m m7_core.cli --analysis-id <uuid> --out <path>

Outputs only the {"pipeline": ...} section owned by M7, read back from the
analysis M7 actually persisted. Emits no event.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def generate_pipeline_output(analysis_id: str) -> dict:
    """Return the pipeline section recorded for a persisted analysis."""
    from m7_core.services.analysis_service import load_stored_document

    doc = load_stored_document(analysis_id)
    if "pipeline" not in doc:
        raise LookupError(
            f"Analysis '{analysis_id}' has no pipeline section recorded; "
            "run the pipeline first. A pipeline section is never synthesised here."
        )
    return {"pipeline": doc["pipeline"]}


def main() -> int:
    parser = argparse.ArgumentParser(description="M7 Core CLI")
    parser.add_argument("--analysis-id", required=True, help="Analysis UUID")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    try:
        out_data = generate_pipeline_output(args.analysis_id)
    except LookupError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
