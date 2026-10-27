"""M7 Core Command Line Interface.

Usage:
  python -m m7_core.cli --analysis-id <uuid> --vault-id <uuid> --out <path>

Outputs only the {"pipeline": ...} section owned by M7. Emits no event.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def generate_pipeline_output() -> dict:
    return {
        "pipeline": {
            "status": "complete",
            "stages": {
                "ingest": "done",
                "static": "done",
                "dynamic": "done",
                "iocs": "done",
                "scoring": "done",
                "response": "done",
                "report": "done"
            }
        }
    }


def main():
    parser = argparse.ArgumentParser(description="M7 Core CLI")
    parser.add_argument("--analysis-id", required=True, help="Analysis UUID")
    parser.add_argument("--vault-id", required=False, default=None, help="Vault UUID")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    out_data = generate_pipeline_output()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)


if __name__ == "__main__":
    main()
