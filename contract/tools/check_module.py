#!/usr/bin/env python3
"""Strict per-module contract gate.

A module's output file is a JSON object keyed by SECTION NAME, e.g. {"static": {...}}.
M5 writes three sections: {"detections": ..., "score": ..., "verdict": ...}.

Checks: (1) only sections the module owns, (2) every owned section present,
(3) each section validates against the JSON Schema, (4) semantic rules,
(5) events: schema, correct producer, allowed event type.

Exit codes: 0 pass, 1 contract violation, 2 cannot check (jsonschema missing).
Use --semantic-only ONLY for quick local runs; CI must not.
"""
import argparse, json, sys
from pathlib import Path
import validate as v

REQUIRED = {"M1": ["sample"], "M2": ["static"], "M3": ["dynamic"], "M4": ["iocs"],
            "M5": ["detections", "score", "verdict"], "M6": ["response_actions"],
            "M7": ["pipeline"], "M8": []}
EVENTS = {"M1": "sample.received", "M2": "static.done", "M3": "dynamic.done",
          "M4": "iocs.done", "M5": "scoring.done", "M6": "response.done",
          "M7": None, "M8": "report.done"}


def section_schema_errors(section, obj):
    schema = v.load_json(v.SCHEMA_DIR / "analysis_result.schema.json")
    wrapper = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{section}"}
    val = v.Draft202012Validator(wrapper, format_checker=v.Draft202012Validator.FORMAT_CHECKER)
    return [f"{section}/{'/'.join(map(str, e.absolute_path))}: {e.message}".replace("/:", ":")
            for e in sorted(val.iter_errors(obj), key=lambda e: list(e.absolute_path))]


def type_errors(doc):
    """Structural guard (no jsonschema needed) so malformed sections fail cleanly."""
    errs = []
    for sec, obj in doc.items():
        want = list if sec == "response_actions" else dict
        if not isinstance(obj, want):
            errs.append(f"section '{sec}' must be a{'n array' if want is list else 'n object'}")
    return errs


def check_output(module, doc, semantic_only=False):
    if module not in REQUIRED:
        return [f"unknown module {module}"]
    if not isinstance(doc, dict) or not doc:
        return ["output must be a non-empty object keyed by section name"]
    errs = v.ownership_errors(module, list(doc))
    errs += [f"missing required section '{s}'" for s in REQUIRED[module] if s not in doc]
    bad = type_errors(doc)
    if bad:
        return errs + bad
    if not semantic_only:
        for sec, obj in doc.items():
            if sec in REQUIRED.get(module, []) or sec in v.load_json(v.SCHEMA_DIR / "analysis_result.schema.json")["$defs"]:
                errs += section_schema_errors(sec, obj)
    if errs and not semantic_only:
        return errs          # semantic rules assume schema-valid input
    return errs + v.semantic_errors(doc)


def check_event(module, ev, semantic_only=False):
    errs = []
    if ev.get("producer") != module:
        errs.append(f"event producer is {ev.get('producer')}, expected {module}")
    allowed = {EVENTS.get(module), "stage.failed"} - {None}
    if ev.get("type") not in allowed:
        errs.append(f"{module} may only emit {sorted(allowed)}, got {ev.get('type')}")
    if not semantic_only:
        errs += v.schema_errors(ev, "events.schema.json")
    return errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", required=True, choices=sorted(REQUIRED))
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="module output (sections)")
    g.add_argument("--event", help="event message")
    ap.add_argument("--semantic-only", action="store_true")
    a = ap.parse_args()
    if v.jsonschema is None and not a.semantic_only:
        print("ERROR: jsonschema not installed (pip install -r requirements.txt)", file=sys.stderr)
        sys.exit(2)
    if a.file:
        errs = check_output(a.module, v.load_json(a.file), a.semantic_only)
    else:
        errs = check_event(a.module, v.load_json(a.event), a.semantic_only)
    for e in errs:
        print("FAIL", e)
    print(f"{a.module}: " + ("CONTRACT OK" if not errs else f"{len(errs)} violation(s)"))
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
