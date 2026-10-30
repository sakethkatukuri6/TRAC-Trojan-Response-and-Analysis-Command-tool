"""
TRAC Master Pipeline Runner
===========================
Orchestrates end-to-end malware analysis across all modules:
M1 (Vault) -> M2 (Static) -> M3 (Dynamic) -> M4 (IOCs) -> M5 (Scoring) -> M6 (Response)

Provides single-entry-point analysis with automatic password-protected ZIP extraction.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple
import uuid
import zipfile

try:
    import pyzipper
except ImportError:
    pyzipper = None

from m1_ingestion.vault import MAX_FILE_SIZE, SampleVault
from m2_static.analyzer import analyze_static
from m3_dynamic.inference_engine import infer_behavior
from m4_ioc.extractor import extract_iocs
from m5_detection.scoring_engine import score_analysis
from m6_response.planner.response_planner import ResponsePlanner

logger = logging.getLogger(__name__)

# Member extensions that identify the executable payload inside a sample archive.
EXECUTABLE_SUFFIXES = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".pif", ".com", ".ocx", ".cpl", ".drv", ".efi", ".msi",
})

# Stages whose owning module returns no status field; a failure here can only be
# reported by the orchestrator, so the message must not claim a module detail it
# does not have.
_STAGE_FALLBACK_ERRORS = {
    "ingest": ("M1_INTAKE_FAILED", "M1 returned no vault record for the submitted payload."),
    "static": ("STATIC_FAILED", "M2 static analysis returned no completed result."),
    "iocs": ("IOCS_FAILED", "M4 indicator extraction returned no completed result."),
    "scoring": ("SCORING_FAILED", "M5 scoring returned no completed result."),
    "response": ("RESPONSE_FAILED", "M6 response planning returned no action list."),
}


class ArchiveRejected(ValueError):
    """An uploaded archive could not be reduced to exactly one safe payload."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _is_unsafe_member_name(name: str) -> bool:
    """True when an archive member is not a plain relative path."""
    if "\x00" in name or ":" in name:
        return True
    path = PurePosixPath(name.replace("\\", "/"))
    return path.is_absolute() or ".." in path.parts


def _member_suffix(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).suffix.lower()


def _member_basename(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).name


def _open_archive(raw_data: bytes) -> Tuple[Any, io.BytesIO]:
    """Open the uploaded archive from memory only."""
    buffer = io.BytesIO(raw_data)
    if pyzipper is not None:
        try:
            return pyzipper.AESZipFile(buffer), buffer
        except Exception:
            buffer.seek(0)
    try:
        return zipfile.ZipFile(buffer), buffer
    except Exception as exc:
        buffer.close()
        raise ArchiveRejected("ARCHIVE_UNSUPPORTED", f"Archive could not be read: {exc}") from exc


def _select_payload(members: List[zipfile.ZipInfo], filename: str) -> zipfile.ZipInfo:
    """Pick the single payload to analyse, refusing ambiguous archives."""
    candidates = [m for m in members if _member_suffix(m.filename) in EXECUTABLE_SUFFIXES]
    if len(candidates) > 1:
        names = ", ".join(sorted(_member_basename(m.filename) for m in candidates[:5]))
        raise ArchiveRejected(
            "ARCHIVE_AMBIGUOUS",
            f"{filename} contains {len(candidates)} executable candidates ({names}); "
            "exactly one payload is analysed per submission.",
        )
    if len(candidates) == 1:
        return candidates[0]
    if len(members) == 1:
        return members[0]
    raise ArchiveRejected(
        "ARCHIVE_UNSUPPORTED",
        f"{filename} contains {len(members)} files and no single executable payload.",
    )


def _read_member(archive: Any, member: zipfile.ZipInfo, password: Optional[str]) -> bytes:
    pwd = password.encode("utf-8") if password else None
    last_error: Optional[BaseException] = None
    for attempt in (pwd, None):
        try:
            return archive.read(member) if attempt is None else archive.read(member, pwd=attempt)
        except Exception as exc:
            last_error = exc
    # The message never echoes the supplied password.
    raise ArchiveRejected(
        "ARCHIVE_UNREADABLE",
        f"{_member_basename(member.filename)} could not be extracted: {last_error}",
    )


def unpack_if_archive(
    raw_data: bytes,
    filename: str,
    password: Optional[str] = "infected",
) -> Tuple[bytes, str]:
    """Reduce a ZIP upload to its single payload, entirely in memory.

    Raises ``ArchiveRejected`` for archives with no file entry, an unsafe member
    name, several executable candidates, an undecryptable payload, or a payload
    that exceeds the contract size cap once decompressed.
    """
    if not (raw_data.startswith(b"PK\x03\x04") or raw_data.startswith(b"PK\x05\x06")):
        return raw_data, filename

    archive, buffer = _open_archive(raw_data)
    try:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if not members:
            raise ArchiveRejected("ARCHIVE_EMPTY", f"{filename} contains no file entry.")

        for member in members:
            if _is_unsafe_member_name(member.filename):
                raise ArchiveRejected(
                    "ARCHIVE_UNSAFE_NAME",
                    f"Archive member {member.filename!r} is not a safe relative path.",
                )

        chosen = _select_payload(members, filename)
        # Checked before decompression so a declared size bomb is never inflated.
        if chosen.file_size > MAX_FILE_SIZE:
            raise ArchiveRejected(
                "PAYLOAD_TOO_LARGE",
                f"{_member_basename(chosen.filename)} decompresses to {chosen.file_size} "
                f"bytes; the cap is {MAX_FILE_SIZE} bytes.",
            )

        payload = _read_member(archive, chosen, password)
        if not payload:
            raise ArchiveRejected(
                "ARCHIVE_EMPTY",
                f"{_member_basename(chosen.filename)} is empty.",
            )
        if len(payload) > MAX_FILE_SIZE:
            raise ArchiveRejected(
                "PAYLOAD_TOO_LARGE",
                f"{_member_basename(chosen.filename)} decompressed to {len(payload)} bytes "
                f"beyond the {MAX_FILE_SIZE} byte cap.",
            )

        return payload, _member_basename(chosen.filename)
    finally:
        archive.close()
        buffer.close()


def run_full_pipeline(
    raw_bytes: bytes,
    original_filename: str,
    archive_password: Optional[str] = "infected",
    vault: Optional[SampleVault] = None,
    analysis_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute full TRAC analysis pipeline and return contract-valid result document.

    `original_filename` is required: the name recorded in the sample section is
    provenance, so a defaulted "sample.exe" would claim a filename nobody supplied
    and assert the payload is a Windows executable.
    """
    # 0. Unpack if password-protected archive
    binary_bytes, active_filename = unpack_if_archive(
        raw_bytes, original_filename, password=archive_password
    )

    aid = analysis_id or str(uuid.uuid4())
    v = vault or SampleVault()

    # 1. M1 Vault Ingestion
    sample_rec, event_rec, is_dup = v.ingest(
        data=binary_bytes,
        original_name=active_filename,
        analysis_id=aid,
    )
    assigned_aid = event_rec.get("analysis_id", aid)

    # 2. M2 Static Analysis
    file_type = sample_rec.get("file_type", "pe")
    static_res = analyze_static(
        data=binary_bytes,
        file_type=file_type,
        filename=sample_rec.get("original_name", active_filename),
    )

    # 3. M3 Dynamic Behavioral Inference
    dynamic_res = infer_behavior(
        data=binary_bytes,
        file_type=file_type,
        static_result=static_res,
        filename=sample_rec.get("original_name", active_filename),
    )

    # 4. M4 IOC Extraction
    iocs_res = extract_iocs(
        data=binary_bytes,
        static_result=static_res,
        dynamic_result=dynamic_res,
        sample_record=sample_rec,
    )

    # 5. M5 Detection and Scoring
    scoring_res = score_analysis(
        data=binary_bytes,
        static_result=static_res,
        dynamic_result=dynamic_res,
        iocs_result=iocs_res,
        sample_record=sample_rec,
    )

    # Prepare cleaned dynamic section without internal markers
    clean_dynamic = dict(dynamic_res)
    clean_dynamic.pop("_static_capabilities", None)
    sandbox_error = clean_dynamic.pop("_error", None)

    # 6. M6 Response Planner
    partial_doc: Dict[str, Any] = {
        "analysis_id": assigned_aid,
        "sample": sample_rec,
        "verdict": scoring_res["verdict"],
        "iocs": iocs_res,
        "dynamic": clean_dynamic,
    }
    planner = ResponsePlanner(mode="dry_run")
    response_actions = planner.plan_response(partial_doc)

    # Each stage status is read back from what the owning module actually returned.
    # A module that reports no status is recorded as failed, never assumed done.
    stages: Dict[str, str] = {
        "ingest": "done" if sample_rec.get("vault_id") else "failed",
        "static": static_res.get("status", "failed"),
        "dynamic": dynamic_res.get("status", "failed"),
        "iocs": iocs_res.get("status", "failed"),
        "scoring": (scoring_res.get("detections") or {}).get("status", "failed"),
        "response": "done" if isinstance(response_actions, list) else "failed",
        # Report generation is M8's own request against the stored document; this
        # pipeline never produces a report, so it cannot claim one.
        "report": "pending",
    }

    pipeline_errors: list[Dict[str, Any]] = []
    for stage, stage_status in stages.items():
        if stage_status != "failed":
            continue
        if stage == "dynamic":
            code = "SANDBOX_FAILED"
            message = sandbox_error or "The configured sandbox did not return a result."
        else:
            code, message = _STAGE_FALLBACK_ERRORS[stage]
        pipeline_errors.append({
            "stage": stage,
            "code": code,
            "message": message[:500],
            "at": datetime.now(timezone.utc).isoformat(),
        })

    # "report" is the state the state machine reaches once response.done is emitted;
    # only M8's report.done moves an analysis to complete.
    pipeline_status = "failed" if "failed" in stages.values() else "report"

    # 7. Assemble Full Contract Document
    doc: Dict[str, Any] = {
        "contract_version": "1.0.0",
        "analysis_id": assigned_aid,
        "sample": sample_rec,
        "pipeline": {
            "status": pipeline_status,
            "stages": stages,
        },
        "static": static_res,
        "dynamic": clean_dynamic,
        "iocs": iocs_res,
        "detections": scoring_res["detections"],
        "score": scoring_res["score"],
        "verdict": scoring_res["verdict"],
        "response_actions": response_actions,
    }

    if pipeline_errors:
        doc["pipeline"]["errors"] = pipeline_errors

    return doc
