"""Contract Loader for M7 Core.

Loads schemas, state machine, and OpenAPI specification from committed contract files
at runtime without copying schema literals into code.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTRACT_DIR = REPO_ROOT / "contract"
SCHEMAS_DIR = CONTRACT_DIR / "schemas"
PIPELINE_DIR = CONTRACT_DIR / "pipeline"
API_DIR = CONTRACT_DIR / "api"

_analysis_schema_cache: Optional[Dict[str, Any]] = None
_events_schema_cache: Optional[Dict[str, Any]] = None
_state_machine_cache: Optional[Dict[str, Any]] = None
_openapi_cache: Optional[Dict[str, Any]] = None


def load_json(p: Path) -> Dict[str, Any]:
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(p: Path) -> Dict[str, Any]:
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_analysis_schema() -> Dict[str, Any]:
    global _analysis_schema_cache
    if _analysis_schema_cache is None:
        _analysis_schema_cache = load_json(SCHEMAS_DIR / "analysis_result.schema.json")
    return _analysis_schema_cache


def get_events_schema() -> Dict[str, Any]:
    global _events_schema_cache
    if _events_schema_cache is None:
        _events_schema_cache = load_json(SCHEMAS_DIR / "events.schema.json")
    return _events_schema_cache


def get_state_machine() -> Dict[str, Any]:
    global _state_machine_cache
    if _state_machine_cache is None:
        _state_machine_cache = load_yaml(PIPELINE_DIR / "state_machine.yaml")
    return _state_machine_cache


def get_openapi_spec() -> Dict[str, Any]:
    global _openapi_cache
    if _openapi_cache is None:
        _openapi_cache = load_yaml(API_DIR / "openapi.yaml")
    return _openapi_cache


def get_section_owners() -> Dict[str, str]:
    sm = get_state_machine()
    return dict(sm.get("section_owners", {}))


def get_owner_for_section(section: str) -> Optional[str]:
    return get_section_owners().get(section)


def validate_section(section: str, obj: Any) -> List[str]:
    schema = get_analysis_schema()
    if section not in schema.get("$defs", {}):
        return [f"unknown section '{section}'"]

    wrapper = {
        "$schema": schema.get("$schema", "https://json-schema.org/draft/2020-12/schema"),
        "$defs": schema.get("$defs", {}),
        "$ref": f"#/$defs/{section}"
    }
    validator = Draft202012Validator(wrapper, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = []
    for err in sorted(validator.iter_errors(obj), key=lambda e: list(e.absolute_path)):
        loc = "/".join(map(str, err.absolute_path))
        prefix = f"{section}/{loc}: " if loc else f"{section}: "
        errors.append(f"{prefix}{err.message}")
    return errors


def validate_event(event_dict: Dict[str, Any]) -> List[str]:
    schema = get_events_schema()
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = []
    for err in sorted(validator.iter_errors(event_dict), key=lambda e: list(e.absolute_path)):
        loc = "/".join(map(str, err.absolute_path))
        prefix = f"event/{loc}: " if loc else "event: "
        errors.append(f"{prefix}{err.message}")
    return errors
