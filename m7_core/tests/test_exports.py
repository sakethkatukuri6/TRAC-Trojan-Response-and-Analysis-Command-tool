"""Exports must come from the module that owns them, never from the router."""
import json
import uuid
from pathlib import Path

import pytest

from m7_core.services.analysis_service import AnalysisService

ROOT = Path(__file__).resolve().parent.parent.parent
TROJAN_FIXTURE = ROOT / "contract" / "examples" / "valid_synthetic_trojan_record.json"


@pytest.fixture
def stored_analysis(client, db_session) -> str:
    """Persist a contract-valid analysis so the router has real state to export."""
    doc = json.loads(TROJAN_FIXTURE.read_text(encoding="utf-8"))
    doc["analysis_id"] = str(uuid.uuid4())
    AnalysisService(db_session).persist_pipeline_result(doc)
    return doc["analysis_id"]


def _export(client, token: str, analysis_id: str, fmt: str):
    return client.get(
        f"/api/v1/analyses/{analysis_id}/export",
        params={"format": fmt},
        headers={"Authorization": f"Bearer {token}"},
    )


def test_stix_export_emits_the_objects_the_analysis_actually_has(client, analyst_token, stored_analysis):
    res = _export(client, analyst_token, stored_analysis, "stix")

    assert res.status_code == 200, res.text
    bundle = res.json()
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["id"] != f"bundle--{stored_analysis}"  # M6 mints the STIX id
    kinds = [obj["type"] for obj in bundle["objects"]]
    assert kinds.count("course-of-action") == 3
    assert kinds.count("indicator") == 3
    patterns = " ".join(obj["pattern"] for obj in bundle["objects"] if obj["type"] == "indicator")
    assert "c2[.]example" in patterns
    assert "192[.]0[.]2[.]10" in patterns


def test_pdf_export_refuses_to_emit_a_synthetic_file(client, analyst_token, stored_analysis):
    res = _export(client, analyst_token, stored_analysis, "pdf")

    assert res.status_code == 501
    assert not res.text.startswith("%PDF")
    assert "M8" in res.json()["detail"]


def test_json_export_still_returns_the_stored_document(client, analyst_token, stored_analysis):
    res = _export(client, analyst_token, stored_analysis, "json")

    assert res.status_code == 200
    assert res.json()["analysis_id"] == stored_analysis


def test_export_of_an_unknown_analysis_is_not_found(client, analyst_token):
    res = _export(client, analyst_token, str(uuid.uuid4()), "stix")

    assert res.status_code == 404


def test_export_requires_a_bearer_token(client, stored_analysis):
    res = client.get(f"/api/v1/analyses/{stored_analysis}/export", params={"format": "stix"})

    assert res.status_code == 401
