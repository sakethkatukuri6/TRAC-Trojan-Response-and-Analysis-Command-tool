#!/usr/bin/env python3
"""Emit contract-valid stub output (and event) for a module, so others can integrate before it exists.
  python tools/stub_module.py M3 --out m3_dynamic/contract_out/dynamic.json
  python tools/stub_module.py M3 --event
"""
import argparse, json, sys
from pathlib import Path
import validate as v
from check_module import REQUIRED, EVENTS

SRC = v.ROOT / "examples" / "valid_synthetic_trojan_record.json"
PAYLOAD = {"sample.received": lambda d: {"sha256": d["sample"]["sha256"], "file_type": d["sample"]["file_type"]},
           "static.done": lambda d: {"section": "static", "yara_match_count": len(d["static"]["yara_matches"])},
           "dynamic.done": lambda d: {"section": "dynamic", "reverted": True},
           "iocs.done": lambda d: {"section": "iocs", "ioc_count": len(d["iocs"]["items"])},
           "scoring.done": lambda d: {"section": "verdict", "label": d["verdict"]["label"], "severity": d["verdict"]["severity"]},
           "response.done": lambda d: {"section": "response_actions", "action_count": len(d["response_actions"])},
           "report.done": lambda d: {"report_vault_id": d["sample"]["vault_id"]}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module", choices=sorted(REQUIRED))
    ap.add_argument("--event", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    doc = v.load_json(SRC)
    if a.event:
        t = EVENTS[a.module]
        if not t:
            sys.exit(f"{a.module} emits no pipeline event")
        out = {"event_id": "00000009-0000-4000-8000-000000000009", "type": t,
               "analysis_id": doc["analysis_id"], "vault_id": doc["sample"]["vault_id"],
               "emitted_at": "2026-10-10T09:00:00Z", "producer": a.module,
               "contract_version": "1.0.0", "payload": PAYLOAD[t](doc)}
    else:
        out = {s: doc[s] for s in REQUIRED[a.module]}
    text = json.dumps(out, indent=2)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text)
    else:
        print(text)


if __name__ == "__main__":
    main()
