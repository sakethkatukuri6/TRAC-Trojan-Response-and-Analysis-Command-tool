import argparse
import json
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path

def defang_url(url: str) -> str:
    url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return re.sub(r'\.', '[.]', url)

def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")

def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")

def create_event(analysis_id: str, count: int) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "type": "iocs.done",
        "analysis_id": analysis_id,
        "vault_id": "00000003-0000-4000-8000-000000000003",
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M4",
        "contract_version": "1.0.0",
        "payload": {
            "section": "iocs",
            "ioc_count": count
        }
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    # Stub data since we aren't parsing real zeek logs right now
    iocs = [
        {
            "type": "domain",
            "value": defang_domain("c2.example"),
            "source": "pcap",
            "confidence": 0.9
        },
        {
            "type": "ip",
            "value": defang_ip("192.0.2.10"),
            "source": "pcap",
            "confidence": 0.8
        },
        {
            "type": "url",
            "value": defang_url("http://c2.example/gate"),
            "source": "static_strings",
            "confidence": 0.85
        },
        {
            "type": "mutex",
            "value": "Global\\SYNTH_MTX_01",
            "source": "dynamic",
            "confidence": 0.7
        },
        {
            "type": "registry_key",
            "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Helper",
            "source": "dynamic",
            "confidence": 0.9
        }
    ]

    out_data = {
        "iocs": {
            "status": "done",
            "items": iocs,
            "attack_techniques": [
                {
                    "id": "T1547.001",
                    "tactic": "persistence",
                    "evidence": "Run key written"
                },
                {
                    "id": "T1071.001",
                    "tactic": "command-and-control",
                    "evidence": "Periodic HTTP to c2[.]example"
                }
            ],
            "beacons": [
                {
                    "destination": "c2[.]example",
                    "interval_s": 20,
                    "jitter": 0.1,
                    "count": 6
                }
            ]
        }
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out_data, f, indent=2)

    # Output the event too
    event_path = out_path.parent.parent / "contract_events" / f"iocs_done.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    with open(event_path, "w") as f:
        json.dump(create_event(args.analysis_id, len(iocs)), f, indent=2)

if __name__ == "__main__":
    main()
