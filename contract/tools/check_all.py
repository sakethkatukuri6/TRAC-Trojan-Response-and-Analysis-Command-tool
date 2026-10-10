#!/usr/bin/env python3
"""CI gate: validate every module's committed golden outputs.
Each module keeps  <dir>/contract_out/*.json  (sections)  and  <dir>/contract_events/*.json  (events).
  python tools/check_all.py --repo-root .. --require-all
"""
import argparse, sys
from pathlib import Path
import validate as v
import check_module as cm

MODULE_DIRS = {"M1": "m1_ingestion", "M2": "m2_static", "M3": "m3_dynamic", "M4": "m4_ioc",
               "M5": "m5_detection", "M6": "m6_response", "M7": "m7_core", "M8": "m8_ui_devops"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--require-all", action="store_true", help="fail if a module has no golden outputs")
    ap.add_argument("--semantic-only", action="store_true")
    a = ap.parse_args()
    if v.jsonschema is None and not a.semantic_only:
        sys.exit("jsonschema not installed")
    bad = 0
    for m, d in MODULE_DIRS.items():
        root = Path(a.repo_root) / d
        outs = sorted((root / "contract_out").glob("*.json"))
        evs = sorted((root / "contract_events").glob("*.json"))
        if not outs and not evs:
            if a.require_all:
                print(f"FAIL {m}: no golden outputs in {d}/contract_out or contract_events"); bad += 1
            else:
                print(f"skip {m}: no outputs yet")
            continue
        errs = []
        for p in outs:
            errs += [f"{p.name}: {e}" for e in cm.check_output(m, v.load_json(p), a.semantic_only)]
        for p in evs:
            errs += [f"{p.name}: {e}" for e in cm.check_event(m, v.load_json(p), a.semantic_only)]
        print(f"{'FAIL' if errs else 'ok  '} {m}")
        for e in errs:
            print("     ", e)
        bad += bool(errs)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
