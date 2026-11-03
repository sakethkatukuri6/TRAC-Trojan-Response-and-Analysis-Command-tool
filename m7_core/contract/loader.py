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


def get_contract_version() -> str:
    """The version every event and analysis document must stamp.

    state_machine.yaml declares it. Producers that hardcode the number would keep
    emitting "1.0.0" envelopes after the contract moves on, and the gate would still
    accept them.
    """
    version = get_state_machine().get("contract_version")
    if not version:
        raise RuntimeError("state_machine.yaml declares no contract_version.")
    return str(version)


def get_max_upload_bytes() -> int:
    """The largest sample the platform accepts, as the contract declares it.

    analysis_result.schema.json caps sample.size_bytes, so that number is the upload
    limit rather than a separate setting. Every intake gate in M1, M7 and M8 enforces
    the same value; if one of them carried its own literal, a file the earlier gate
    waved through would be rejected later as a schema violation instead of a 413.
    """
    size_bytes = (
        get_analysis_schema().get("$defs", {}).get("sample", {}).get("properties", {}).get("size_bytes", {})
    )
    cap = size_bytes.get("maximum")
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        raise RuntimeError(
            "analysis_result.schema.json declares no positive integer maximum on "
            "sample.size_bytes, so the upload cap cannot be determined."
        )
    return cap


def get_openapi_spec() -> Dict[str, Any]:
    global _openapi_cache
    if _openapi_cache is None:
        _openapi_cache = load_yaml(API_DIR / "openapi.yaml")
    return _openapi_cache


def get_platform_version() -> str:
    """The API version openapi.yaml declares, which every module reports."""
    version = (get_openapi_spec().get("info") or {}).get("version")
    if not version:
        raise RuntimeError("openapi.yaml declares no info.version.")
    return str(version)


def get_m7_base_url() -> str:
    """The M7 API origin published by openapi.yaml, without its /api/v1 prefix.

    servers[0].url is the contract's statement of where the API lives. A module that
    hardcodes its own origin keeps calling a host the deployment no longer uses, and
    the failure surfaces as an unexplained connection error rather than as a
    contract mismatch.
    """
    servers = get_openapi_spec().get("servers") or []
    url = str((servers[0] if servers else {}).get("url", "")).strip()
    if not url:
        raise RuntimeError("openapi.yaml declares no servers[0].url.")
    prefix = "/api/v1"
    if url.endswith(prefix):
        url = url[: -len(prefix)]
    return url.rstrip("/")


def get_final_states() -> List[str]:
    """Pipeline states from which no further work is possible.

    state_machine.yaml does not mark these, but it says everything else: a state
    that never appears as some transition's `from` cannot be left, so it is where
    the analysis ends. Deriving the set means a new terminal state cannot be added
    to the contract and stay writable in code.
    """
    sm = get_state_machine()
    states = list(sm.get("states", []))
    if not states:
        raise RuntimeError("state_machine.yaml declares no states.")
    left = {str(tr.get("from")) for tr in sm.get("transitions", [])}
    return [s for s in states if s not in left]


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
