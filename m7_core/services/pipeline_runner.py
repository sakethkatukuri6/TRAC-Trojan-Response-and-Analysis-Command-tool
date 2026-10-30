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
from typing import Any, Dict, Optional, Tuple
import uuid
import zipfile

try:
    import pyzipper
except ImportError:
    pyzipper = None

from m1_ingestion.vault import SampleVault
from m2_static.analyzer import analyze_static
from m3_dynamic.inference_engine import infer_behavior
from m4_ioc.extractor import extract_iocs
from m5_detection.scoring_engine import score_analysis
from m6_response.planner.response_planner import ResponsePlanner

logger = logging.getLogger(__name__)


def unpack_if_archive(
    raw_data: bytes,
    filename: str,
    password: Optional[str] = "infected",
) -> Tuple[bytes, str]:
    """Auto-extract executable payload if raw_data is a password-protected or standard ZIP."""
    if not (raw_data.startswith(b"PK\x03\x04") or raw_data.startswith(b"PK\x05\x06")):
        return raw_data, filename

    pwd_bytes = password.encode("utf-8") if password else b"infected"

    # Attempt pyzipper first for WinZip AES support
    if pyzipper is not None:
        try:
            with pyzipper.AESZipFile(io.BytesIO(raw_data)) as zf:
                names = zf.namelist()
                for name in names:
                    if not name.endswith("/"):
                        try:
                            extracted = zf.read(name, pwd=pwd_bytes)
                            if len(extracted) > 0:
                                return extracted, name
                        except Exception:
                            # Try without password
                            try:
                                extracted = zf.read(name)
                                if len(extracted) > 0:
                                    return extracted, name
                            except Exception:
                                pass
        except Exception:
            pass

    # Standard zipfile fallback
    try:
        with zipfile.ZipFile(io.BytesIO(raw_data)) as zf:
            for name in zf.namelist():
                if not name.endswith("/"):
                    try:
                        extracted = zf.read(name, pwd=pwd_bytes)
                        if len(extracted) > 0:
                            return extracted, name
                    except Exception:
                        try:
                            extracted = zf.read(name)
                            if len(extracted) > 0:
                                return extracted, name
                        except Exception:
                            pass
    except Exception:
        pass

    return raw_data, filename


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
    clean_dynamic.pop("_detected_behaviors", None)

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

    # 7. Assemble Full Contract Document
    doc: Dict[str, Any] = {
        "contract_version": "1.0.0",
        "analysis_id": assigned_aid,
        "sample": sample_rec,
        "pipeline": {
            "status": "complete",
            "stages": {
                "ingest": "done",
                "static": "done",
                "dynamic": "done",
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

    return doc
