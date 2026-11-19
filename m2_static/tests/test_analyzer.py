"""Comprehensive test suite for M2 Static Analysis Engine & CLI."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
import pytest

from contract.tools.validate import validate_document
from m2_static.analyzer import analyze_static
from m7_core.tests.benign_pe import expected_imports

FIXTURE_IMPHASH = "ad401b7b793a5b016852bd9708098744"


def test_benign_pe_analysis(benign_pe_bytes: bytes):
    """Test full static extraction from valid in-memory PE32+ binary."""
    res = analyze_static(benign_pe_bytes, file_type="pe", filename="benign.exe")

    assert res["status"] == "done"
    assert res["file_class"] == "pe"
    assert 0.0 <= res["entropy"] <= 8.0
    assert "pe" in res

    pe = res["pe"]
    assert pe["compile_time"].startswith("2020-07-17T04:10:27")
    assert pe["imphash"] == FIXTURE_IMPHASH
    assert pe["is_dll"] is False
    assert pe["signed"] is False

    sections = {s["name"]: s for s in pe["sections"]}
    assert ".text" in sections
    assert ".rdata" in sections
    assert 0.0 <= sections[".text"]["entropy"] <= 8.0

    imports = pe["imports"]
    assert sorted(imports) == sorted(expected_imports())


def test_non_pe_strings_and_urls():
    """Test strings extraction and URL defanging on non-PE text content."""
    sample = (
        b"Welcome to test system. "
        b"Contact us at https://malicious.evil.com/gate.php and http://192.168.1.55:8080/c2. "
        b"Internal mutex Global\\TestSampleMutex created."
    )
    res = analyze_static(sample, file_type="script", filename="script.ps1")

    assert res["status"] == "done"
    assert res["file_class"] == "script"
    assert "pe" not in res
    assert res["packers"] == []

    # Verify URLs are found and defanged with bracketed dots
    urls = res["embedded_urls"]
    assert any("hxxps://" in u and "malicious[.]evil[.]com" in u for u in urls)
    assert any("hxxp://" in u and "192[.]168[.]1[.]55" in u for u in urls)

    # Verify interesting strings contain mutex
    interesting = res["strings"]["interesting"]
    assert any("Global\\TestSampleMutex" in s for s in interesting)


def test_corrupted_pe_handled_gracefully():
    """Malformed PE bytes must fail gracefully with status=failed instead of crashing."""
    corrupted = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
    res = analyze_static(corrupted, file_type="pe", filename="corrupt.exe")

    assert res["status"] == "failed"
    assert res["packers"] == []
    assert 0.0 <= res["entropy"] <= 8.0


def test_empty_payload_handled_gracefully():
    """Empty payload should return a clean response without exceptions."""
    res = analyze_static(b"", file_type="unknown", filename="empty.bin")
    assert res["status"] == "done"
    assert res["entropy"] == 0.0
    assert res["strings"]["count"] == 0
    assert res["embedded_urls"] == []


def test_cli_execution_on_file(tmp_path: Path, benign_pe_bytes: bytes):
    """Test executing M2 CLI on a raw file directly."""
    sample_file = tmp_path / "sample.exe"
    sample_file.write_bytes(benign_pe_bytes)

    out_file = tmp_path / "static_out.json"
    event_file = tmp_path / "static_event.json"

    cmd = [
        sys.executable,
        "-m",
        "m2_static.cli",
        "--file",
        str(sample_file),
        "--file-type",
        "pe",
        "--out",
        str(out_file),
        "--event-out",
        str(event_file),
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"CLI failed: {proc.stderr}"
    assert out_file.exists()
    assert event_file.exists()

    out_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "static" in out_data
    assert out_data["static"]["status"] == "done"
    assert out_data["static"]["pe"]["imphash"] == FIXTURE_IMPHASH

    event_data = json.loads(event_file.read_text(encoding="utf-8"))
    assert event_data["type"] == "static.done"
    assert event_data["producer"] == "M2"
    assert event_data["payload"]["section"] == "static"


def test_contract_compliance_via_validator(benign_pe_bytes: bytes):
    """Ensure static analysis embeds cleanly into a complete valid contract document."""
    res = analyze_static(benign_pe_bytes, file_type="pe", filename="benign.exe")

    doc = {
        "contract_version": "1.0.0",
        "analysis_id": "00000003-0000-4000-8000-000000000003",
        "sample": {
            "vault_id": "00000003-0000-4000-8000-000000000003",
            "sha256": "872820ddbb0c8d0b90c7bb16f1a3930b3aa1031f61d184771b6fce828c08daae",
            "md5": "00000000000000000000000000000000",
            "size_bytes": len(benign_pe_bytes),
            "file_type": "pe",
            "original_name": "benign.exe",
            "stored_defanged": True,
            "stored_encrypted": True,
            "clamav_result": "not_run",
            "received_at": "2026-10-10T09:00:00Z",
        },
        "static": res,
        "pipeline": {
            "status": "dynamic",
            "stages": {
                "ingest": "done",
                "static": "done",
                "dynamic": "running",
            },
        },
    }

    errors = validate_document(doc)
    assert errors == [], f"Contract validation failed: {errors}"
