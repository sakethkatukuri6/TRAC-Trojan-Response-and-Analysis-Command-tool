import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

def create_event(analysis_id: str) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "type": "scoring.done",
        "analysis_id": analysis_id,
        "vault_id": "00000003-0000-4000-8000-000000000003",
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M5",
        "contract_version": "1.0.0",
        "payload": {
            "section": "verdict",
            "label": "malicious",
            "severity": "high"
        }
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out_data = {
        "detections": {
            "status": "done",
            "items": [
                {
                    "rule_id": "SYNTH_Loader_Generic",
                    "kind": "yara",
                    "severity": "high",
                    "attack_ids": ["T1027"],
                    "tags": ["loader"]
                },
                {
                    "rule_id": "sigma_runkey_persistence",
                    "kind": "sigma",
                    "severity": "medium",
                    "attack_ids": ["T1547.001"]
                },
                {
                    "rule_id": "behavior_c2_beaconing",
                    "kind": "behavior",
                    "severity": "high",
                    "attack_ids": ["T1071.001"]
                }
            ],
            "intel_hits": [
                {
                    "provider": "malwarebazaar",
                    "indicator": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "result": "unknown"
                }
            ]
        },
        "score": {
            "value": 88,
            "method": "ensemble",
            "model_version": "ens-0.1",
            "components": [
                {
                    "name": "static_findings",
                    "weight": 0.3,
                    "contribution": 24
                },
                {
                    "name": "behaviors",
                    "weight": 0.5,
                    "contribution": 50
                },
                {
                    "name": "ml",
                    "weight": 0.2,
                    "contribution": 14
                }
            ]
        },
        "verdict": {
            "label": "malicious",
            "severity": "high",
            "confidence": 0.91,
            "family_guess": "generic_loader",
            "behavior_tags": [
                "persistence",
                "c2_beaconing",
                "packed"
            ],
            "explanation": [
                "Packed (UPX) with high-entropy sections",
                "Run-key persistence",
                "Periodic HTTP beaconing at ~20s interval"
            ]
        }
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out_data, f, indent=2)

    # Output the event too
    event_path = out_path.parent.parent / "contract_events" / f"scoring_done.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    with open(event_path, "w") as f:
        json.dump(create_event(args.analysis_id), f, indent=2)

if __name__ == "__main__":
    main()
