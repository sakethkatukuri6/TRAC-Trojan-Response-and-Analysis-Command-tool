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
    original_filename: str = "sample.exe",
    archive_password: Optional[str] = "infected",
    vault: Optional[SampleVault] = None,
    analysis_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute full TRAC analysis pipeline and return contract-valid result document."""
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

    pipeline_errors: list[Dict[str, Any]] = []
    if dynamic_res.get("status") == "failed":
        pipeline_errors.append({
            "stage": "dynamic",
            "code": "SANDBOX_FAILED",
            "message": (sandbox_error or "The configured sandbox did not return a result.")[:500],
            "at": datetime.now(timezone.utc).isoformat(),
        })

    # 7. Assemble Full Contract Document
    doc: Dict[str, Any] = {
        "contract_version": "1.0.0",
        "analysis_id": assigned_aid,
        "sample": sample_rec,
        "pipeline": {
            "status": "failed" if dynamic_res.get("status") == "failed" else "complete",
            "stages": {
                "ingest": "done",
                "static": "done",
                "dynamic": dynamic_res.get("status", "failed"),
                "iocs": "done",
                "scoring": "done",
                "response": "done",
                "report": "done",
            },
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
