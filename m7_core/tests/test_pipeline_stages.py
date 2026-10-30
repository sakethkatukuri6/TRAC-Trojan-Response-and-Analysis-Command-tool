"""The pipeline records the statuses each module actually returned.

A generated benign PE is analysed here; nothing is executed and no sandbox is
configured, so the report stage in particular must never be claimed as done.
"""
from __future__ import annotations

import pytest

from contract.tools.validate import validate_document
from m7_core.services import pipeline_runner
from m7_core.services.pipeline_runner import run_full_pipeline
from m7_core.tests.benign_pe import build_benign_pe

PE = build_benign_pe()


@pytest.fixture
def isolated_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_STORAGE_PATH", str(tmp_path / "vault"))
    monkeypatch.delenv("TRAC_CAPE_URL", raising=False)
    monkeypatch.delenv("TRAC_CAPE_TOKEN", raising=False)
    return tmp_path / "vault"


def test_a_finished_pipeline_leaves_the_report_stage_pending(isolated_vault):
    document = run_full_pipeline(PE, original_filename="pe_fixture.exe")

    assert document["pipeline"]["status"] == "report"
    assert document["pipeline"]["stages"]["report"] == "pending"
    assert document["pipeline"]["stages"]["static"] == "done"
    assert "errors" not in document["pipeline"]
    assert validate_document(document) == []


def test_a_stage_that_reports_no_status_is_recorded_as_failed(isolated_vault, monkeypatch):
    monkeypatch.setattr(
        pipeline_runner, "analyze_static", lambda **_kwargs: {"file_class": "unknown"}
    )

    document = run_full_pipeline(PE, original_filename="pe_fixture.exe")

    assert document["pipeline"]["stages"]["static"] == "failed"
    assert document["pipeline"]["status"] == "failed"
    failures = {err["stage"]: err["code"] for err in document["pipeline"]["errors"]}
    assert failures == {"static": "STATIC_FAILED"}


def test_a_real_static_failure_is_not_recorded_as_a_finished_analysis(isolated_vault):
    truncated = PE[:64] + b"\x00" * 32

    document = run_full_pipeline(truncated, original_filename="truncated.exe")

    assert document["static"]["status"] == "failed"
    assert document["pipeline"]["stages"]["static"] == "failed"
    assert document["pipeline"]["status"] == "failed"
