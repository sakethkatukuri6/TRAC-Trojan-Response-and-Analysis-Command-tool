"""Contract accessors: the single place M7 and every other module read platform config from.

These values used to be repeated as literals across M1-M8, which meant a contract
change left some modules enforcing the old number. Each test here ties an accessor to
the file it claims to read and checks it fails closed when the file stops declaring it.
"""
import pytest

from m1_ingestion.vault import MAX_FILE_SIZE
from m7_core.contract import loader
from m7_core.contract.loader import (
    get_contract_version,
    get_final_states,
    get_max_upload_bytes,
    get_m7_base_url,
    get_platform_version,
)


def test_contract_version_matches_the_state_machine():
    assert get_contract_version() == str(loader.get_state_machine()["contract_version"])


def test_platform_version_matches_the_published_api():
    assert get_platform_version() == str(loader.get_openapi_spec()["info"]["version"])


def test_upload_cap_matches_the_schema_maximum():
    schema_max = loader.get_analysis_schema()["$defs"]["sample"]["properties"]["size_bytes"]["maximum"]
    assert get_max_upload_bytes() == schema_max
    # M1 binds the cap as MAX_FILE_SIZE and M7/M8 enforce that same name on upload.
    assert MAX_FILE_SIZE == schema_max


def test_m7_base_url_is_the_published_server_without_its_prefix():
    assert get_m7_base_url() + "/api/v1" == loader.get_openapi_spec()["servers"][0]["url"]


def test_final_states_are_the_states_no_transition_leaves():
    sm = loader.get_state_machine()
    left_by = {tr["from"] for tr in sm["transitions"]}
    expected = [s for s in sm["states"] if s not in left_by]

    assert get_final_states() == expected
    assert set(expected) == {"complete", "failed", "dead_letter"}
    # 'received' is the intake state and 'report' feeds complete, so neither is final.
    assert "received" not in expected and "report" not in expected


def test_section_writers_are_the_contract_owners_minus_pipeline():
    from m7_core.services.analysis_service import AnalysisService

    owners = loader.get_state_machine()["section_owners"]
    assert AnalysisService.SECTION_WRITERS == {s: o for s, o in owners.items() if s != "pipeline"}
    assert "pipeline" not in AnalysisService.SECTION_WRITERS
    assert AnalysisService.SECTION_WRITERS["iocs"] == "M4"


def test_missing_contract_version_fails_closed(monkeypatch):
    monkeypatch.setattr(loader, "_state_machine_cache", {"states": []})
    with pytest.raises(RuntimeError, match="contract_version"):
        get_contract_version()


def test_no_declared_states_fails_closed(monkeypatch):
    monkeypatch.setattr(loader, "_state_machine_cache", {"transitions": []})
    with pytest.raises(RuntimeError, match="no states"):
        get_final_states()


def test_missing_platform_version_fails_closed(monkeypatch):
    monkeypatch.setattr(loader, "_openapi_cache", {"paths": {}})
    with pytest.raises(RuntimeError, match="info.version"):
        get_platform_version()


def test_missing_server_origin_fails_closed(monkeypatch):
    monkeypatch.setattr(loader, "_openapi_cache", {"info": {"version": "1.0.0"}, "servers": []})
    with pytest.raises(RuntimeError, match=r"servers\[0\]\.url"):
        get_m7_base_url()


def test_missing_size_cap_fails_closed(monkeypatch):
    monkeypatch.setattr(
        loader,
        "_analysis_schema_cache",
        {"$defs": {"sample": {"properties": {"size_bytes": {"type": "integer"}}}}},
    )
    with pytest.raises(RuntimeError, match="size_bytes"):
        get_max_upload_bytes()
