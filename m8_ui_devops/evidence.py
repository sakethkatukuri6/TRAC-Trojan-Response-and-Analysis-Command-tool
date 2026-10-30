"""Evidence presentation model for the TRAC M8 command console.

Single source of truth for how a pipeline result is labelled in the dashboard
and in generated reports. Nothing here invents telemetry: runtime facts are
surfaced only when M3 reported ``dynamic.status == "done"``, while everything
derived from the submitted bytes, imports or strings stays under
``Static evidence``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

STATIC_EVIDENCE_LABEL = "Static evidence"
CAPABILITY_LABEL = "Static capability indicators"
OBSERVED_SANDBOX_LABEL = "Observed sandbox telemetry"
SANDBOX_NOT_CONFIGURED_LABEL = "Sandbox not configured"
SANDBOX_FAILED_LABEL = "Sandbox failed"
SANDBOX_NOT_RUN_LABEL = "Sandbox not run"

NOT_CONFIGURED_DETAIL = (
    "No sandbox endpoint is configured for this run, so the sample was never executed. "
    "Configure an isolated sandbox to collect runtime telemetry."
)
NOT_RUN_DETAIL = "The dynamic stage did not complete for this analysis."
GENERIC_FAILURE_DETAIL = "The configured sandbox did not return a result for this run."


def sandbox_status_label(status: Optional[str]) -> str:
    """Map a dynamic stage status onto its operator-facing label."""
    normalized = (status or "").strip().lower()
    if normalized == "done":
        return OBSERVED_SANDBOX_LABEL
    if normalized == "skipped":
        return SANDBOX_NOT_CONFIGURED_LABEL
    if normalized == "failed":
        return SANDBOX_FAILED_LABEL
    return SANDBOX_NOT_RUN_LABEL


def _stage_error(doc: Dict[str, Any], stage: str) -> Optional[str]:
    for err in (doc.get("pipeline") or {}).get("errors") or []:
        if str(err.get("stage", "")).strip().lower() == stage:
            message = str(err.get("message", "")).strip()
            if message:
                return message
    return None


def _observed_telemetry(dynamic: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sandbox": dynamic.get("sandbox") or {},
        "process_tree": dynamic.get("process_tree") or [],
        "file_events": dynamic.get("file_events") or [],
        "registry_events": dynamic.get("registry_events") or [],
        "mutexes": dynamic.get("mutexes") or [],
        "dropped_files": dynamic.get("dropped_files") or [],
        "api_summary": dynamic.get("api_summary") or {},
        "network_summary": dynamic.get("network_summary") or {},
    }


def build_presentation(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Turn a contract analysis document into a labelled evidence view model."""
    doc = doc or {}
    sample = doc.get("sample") or {}
    static = doc.get("static") or {}
    pe = static.get("pe") or {}
    dynamic = doc.get("dynamic") or {}
    iocs = doc.get("iocs") or {}
    detections = doc.get("detections") or {}
    pipeline = doc.get("pipeline") or {}

    status = str(dynamic.get("status") or "").strip().lower()
    observed = status == "done"
    label = sandbox_status_label(status)

    if status == "failed":
        detail = _stage_error(doc, "dynamic") or GENERIC_FAILURE_DETAIL
    elif status == "skipped":
        detail = NOT_CONFIGURED_DETAIL
    elif observed:
        detail = ""
    else:
        detail = NOT_RUN_DETAIL

    sandbox: Dict[str, Any] = {
        "status": status or "unknown",
        "label": label,
        "observed": observed,
        "detail": detail,
        "error": detail if status == "failed" else None,
        "telemetry": _observed_telemetry(dynamic) if observed else None,
    }

    static_evidence: Dict[str, Any] = {
        "label": STATIC_EVIDENCE_LABEL,
        "status": static.get("status"),
        "file_class": static.get("file_class"),
        "entropy": static.get("entropy"),
        "packers": static.get("packers") or [],
        "pe": {
            "signed": pe.get("signed"),
            "is_dll": pe.get("is_dll"),
            "imphash": pe.get("imphash"),
            "compile_time": pe.get("compile_time"),
            "sections": pe.get("sections") or [],
            "imports": pe.get("imports") or [],
            "exports": pe.get("exports") or [],
        },
        "strings": static.get("strings") or {},
        "yara_matches": static.get("yara_matches") or [],
        "embedded_urls": static.get("embedded_urls") or [],
        "sample": {
            "vault_id": sample.get("vault_id"),
            "original_name": sample.get("original_name"),
            "size_bytes": sample.get("size_bytes"),
            "file_type": sample.get("file_type"),
            "received_at": sample.get("received_at"),
            "clamav_result": sample.get("clamav_result", "not_run"),
            "sha256": sample.get("sha256"),
            "md5": sample.get("md5"),
            "sha1": sample.get("sha1"),
        },
    }

    capabilities: Dict[str, Any] = {
        "label": CAPABILITY_LABEL,
        "techniques": iocs.get("attack_techniques") or [],
        "detections": detections.get("items") or [],
        "intel_hits": detections.get("intel_hits") or [],
    }

    iocs_view: Dict[str, Any] = {
        "label": "Defanged indicators",
        "items": iocs.get("items") or [],
        "beacons": (iocs.get("beacons") or []) if observed else [],
    }

    return {
        "analysis_id": doc.get("analysis_id"),
        "pipeline": {
            "status": pipeline.get("status"),
            "stages": pipeline.get("stages") or {},
        },
        "static_evidence": static_evidence,
        "capabilities": capabilities,
        "sandbox": sandbox,
        "iocs": iocs_view,
        "detections": detections,
        "verdict": doc.get("verdict") or {},
        "score": doc.get("score") or {},
        "response_actions": doc.get("response_actions") or [],
    }


def static_evidence_lines(presentation: Dict[str, Any]) -> List[str]:
    """Summarise the static evidence for operator-facing summaries."""
    static = (presentation or {}).get("static_evidence") or {}
    sample = static.get("sample") or {}
    lines = [
        f"SHA-256 {sample.get('sha256') or 'n/a'}",
        f"MD5 {sample.get('md5') or 'n/a'}",
    ]
    entropy = static.get("entropy")
    if entropy is not None:
        lines.append(f"entropy {entropy}")
    if static.get("packers"):
        lines.append("packers: " + ", ".join(static["packers"]))
    lines.append(f"{len((static.get('pe') or {}).get('imports') or [])} imports")
    lines.append(f"{len((static.get('strings') or {}).get('interesting') or [])} interesting strings")
    return lines
