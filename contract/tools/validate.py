#!/usr/bin/env python3
"""Contract validator.

Layer 1: JSON Schema (needs `pip install jsonschema`).
Layer 2: semantic rules the schema cannot express (stdlib only).
Layer 3: section-ownership and event-flow checks from pipeline/state_machine.yaml.

Usage:
  python tools/validate.py examples/valid_synthetic_trojan_record.json
  python tools/validate.py --events some_event.json
"""
import argparse, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"
STATE_MACHINE = ROOT / "pipeline" / "state_machine.yaml"

try:
    import jsonschema
    from jsonschema import Draft202012Validator
except ImportError:  # semantic layer still works without it
    jsonschema = None

LIVE_URL = re.compile(r"\b(?:https?|ftp)://", re.I)
RAW_DOTTED = re.compile(r"[A-Za-z0-9-]\.[A-Za-z0-9]")  # a "." not wrapped in [ ]
STAGE_DONE = {"done", "skipped"}


def load_json(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def schema_errors(doc, schema_name="analysis_result.schema.json"):
    if jsonschema is None:
        raise RuntimeError("jsonschema is not installed (pip install jsonschema)")
    schema = load_json(SCHEMA_DIR / schema_name)
    v = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
            for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))]


def _is_defanged(ioc_type, value):
    if ioc_type == "url":
        return not LIVE_URL.search(value) and ("hxxp" in value.lower() or "[.]" in value or "[:]" in value)
    if ioc_type in ("domain", "ip"):
        return not RAW_DOTTED.search(value)
    return True


def semantic_errors(doc):
    errs = []
    # 1. IOC and embedded-URL defanging
    for i, ioc in enumerate((doc.get("iocs") or {}).get("items", [])):
        if not _is_defanged(ioc.get("type"), ioc.get("value", "")):
            errs.append(f"iocs/items/{i}: {ioc['type']} value is not defanged")
    for i, u in enumerate((doc.get("static") or {}).get("embedded_urls", [])):
        if LIVE_URL.search(u):
            errs.append(f"static/embedded_urls/{i}: live URL, must be defanged")

    # 2. Pipeline consistency
    p = doc.get("pipeline", {})
    if p.get("status") == "complete":
        bad = [k for k, v in p.get("stages", {}).items() if v not in STAGE_DONE]
        if bad:
            errs.append(f"pipeline: status is complete but stages not finished: {bad}")

    # 3. Score / verdict consistency
    score, verdict = doc.get("score"), doc.get("verdict")
    if score:
        total = sum(c["contribution"] for c in score.get("components", []))
        if abs(total - score["value"]) > 1.0:
            errs.append(f"score: components sum to {total}, value is {score['value']}")
    if score and verdict:
        if verdict["label"] == "malicious" and score["value"] < 60:
            errs.append("verdict: 'malicious' requires score >= 60")
        if verdict["label"] == "benign" and score["value"] > 30:
            errs.append("verdict: 'benign' requires score <= 30")
    if verdict and verdict["label"] == "malicious" and verdict["severity"] == "info":
        errs.append("verdict: 'malicious' cannot have severity 'info'")

    # 4. Sandbox safety
    dyn = doc.get("dynamic") or {}
    sb = dyn.get("sandbox")
    if dyn.get("status") == "done" and sb and sb.get("reverted") is not True:
        errs.append("dynamic/sandbox: snapshot must be reverted after run")
    return errs


def ownership_errors(module, sections):
    import yaml
    owners = yaml.safe_load(STATE_MACHINE.read_text())["section_owners"]
    return [f"{module} may not write '{s}' (owner: {owners.get(s, 'nobody')})"
            for s in sections if owners.get(s) != module]


def event_flow_errors(events):
    """Check an ordered list of events follows the state machine."""
    import yaml
    sm = yaml.safe_load(STATE_MACHINE.read_text())
    nxt = {t["event"]: (t["from"], t["to"]) for t in sm["transitions"]}
    state, errs = "received", []
    for i, ev in enumerate(events):
        t = ev["type"]
        if t == "stage.failed":
            continue
        if t not in nxt:
            errs.append(f"event {i}: unknown type {t}")
            continue
        frm, to = nxt[t]
        if frm != state:
            errs.append(f"event {i}: {t} not allowed from state '{state}' (expected '{frm}')")
        else:
            state = to
    return errs


def validate_document(doc):
    return (schema_errors(doc) if jsonschema else []) + semantic_errors(doc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--events", action="store_true", help="file is a single event, not an analysis result")
    a = ap.parse_args()
    doc = load_json(a.file)
    if a.events:
        errs = schema_errors(doc, "events.schema.json")
    else:
        errs = validate_document(doc)
        if jsonschema is None:
            print("warning: jsonschema not installed; only semantic checks ran", file=sys.stderr)
    for e in errs:
        print("FAIL", e)
    print("OK" if not errs else f"{len(errs)} error(s)")
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
