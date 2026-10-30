"""Regression coverage for the real PE static-analysis path (M1 classify + M2 parse).

The fixture is a generated, benign PE32+ image. It is never executed, so the
dynamic stage must stay skipped, and no runtime fact may appear in the result.
"""
from __future__ import annotations

import hashlib

import pytest

from contract.tools.validate import validate_document
from m1_ingestion.classifier import classify_file
from m2_static.analyzer import analyze_static
from m7_core.services.pipeline_runner import run_full_pipeline
from m7_core.tests.benign_pe import build_benign_pe, expected_imports

FIXTURE_SHA256 = "872820ddbb0c8d0b90c7bb16f1a3930b3aa1031f61d184771b6fce828c08daae"
FIXTURE_IMPHASH = "ad401b7b793a5b016852bd9708098744"


@pytest.fixture(scope="module")
def benign_pe() -> bytes:
    return build_benign_pe()


@pytest.fixture
def isolated_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_STORAGE_PATH", str(tmp_path / "vault"))
    monkeypatch.delenv("TRAC_CAPE_URL", raising=False)
    monkeypatch.delenv("TRAC_CAPE_TOKEN", raising=False)
    return tmp_path / "vault"


def test_fixture_is_deterministic_and_benign(benign_pe):
    assert benign_pe == build_benign_pe()
    assert hashlib.sha256(benign_pe).hexdigest() == FIXTURE_SHA256
    assert classify_file(benign_pe, "fixture.exe") == ("pe", "application/x-dosexec")


def test_m2_parses_real_sections_and_imports(benign_pe):
    result = analyze_static(benign_pe, "pe", "fixture.exe")

    assert result["status"] == "done"
    assert result["file_class"] == "pe"
    assert [section["name"] for section in result["pe"]["sections"]] == [".text", ".rdata"]
    assert all(0.0 <= section["entropy"] <= 8.0 for section in result["pe"]["sections"])
    assert all(section["raw_size"] > 0 for section in result["pe"]["sections"])
    assert sorted(result["pe"]["imports"]) == sorted(expected_imports())
    assert result["pe"]["imphash"] == FIXTURE_IMPHASH
    assert result["pe"]["is_dll"] is False
    assert result["pe"]["compile_time"].startswith("2020-07-17T04:10:27")
    assert result["packers"] == []
    assert result["strings"]["count"] > 0


def test_m2_reports_failure_instead_of_inventing_pe_metadata(benign_pe):
    truncated = benign_pe[:64] + b"\x00" * 32
    result = analyze_static(truncated, "pe", "truncated.exe")

    assert result["status"] == "failed"
    assert "pe" not in result or result.get("pe", {}).get("imports", []) == []
    assert result["packers"] == []


def test_pipeline_analyses_a_real_pe_end_to_end(benign_pe, isolated_vault):
    document = run_full_pipeline(benign_pe, original_filename="pe_fixture.exe")

    assert validate_document(document) == []
    assert document["sample"]["file_type"] == "pe"
    assert document["sample"]["size_bytes"] == len(benign_pe)
    assert document["sample"]["sha256"] == FIXTURE_SHA256
    assert document["pipeline"]["status"] == "complete"
    assert document["pipeline"]["stages"]["static"] == "done"
    assert document["static"]["file_class"] == "pe"
    assert len(document["static"]["pe"]["sections"]) == 2
    assert len(document["static"]["pe"]["imports"]) == 3
    assert document["static"]["pe"]["imphash"] == FIXTURE_IMPHASH


def test_real_pe_without_a_sandbox_claims_no_runtime_evidence(benign_pe, isolated_vault):
    document = run_full_pipeline(benign_pe, original_filename="pe_fixture.exe")

    assert document["dynamic"] == {"status": "skipped"}
    assert document["pipeline"]["status"] == "complete"
    assert "errors" not in document["pipeline"]
    assert document["iocs"]["beacons"] == []
    for action in document["response_actions"]:
        assert action["mode"] == "dry_run"
        assert action["status"] == "proposed"


def test_pe_payload_is_only_stored_encrypted(benign_pe, isolated_vault):
    run_full_pipeline(benign_pe, original_filename="pe_fixture.exe")

    stored = sorted(isolated_vault.iterdir())
    assert [path for path in stored if path.suffix == ".vault"]
    for path in stored:
        assert path.suffix in {".vault", ".key"} or path.name == "vault_registry.json"
        assert benign_pe not in path.read_bytes()
