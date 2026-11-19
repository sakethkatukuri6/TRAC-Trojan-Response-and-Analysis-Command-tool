"""What M2 publishes must be enough for M4 and M5 to work from, without a second parse.

`analyze_static` is the only M2 output anyone else sees, so these tests read the
published section rather than the private :class:`PeEvidence` object.
"""
from __future__ import annotations

import pytest

from contract.tools.validate import semantic_errors
from m2_static.analyzer import analyze_static
from m2_static.pe_evidence import capability_meta, group_imports
from m2_static.tests import pe_mutants as pe
from m7_core.tests.benign_pe import build_benign_pe, expected_imports


@pytest.fixture(scope="module")
def benign():
    return pe.benign_pe()


def _static(data: bytes, filename: str = "sample.exe") -> dict:
    return analyze_static(data=data, file_type="pe", filename=filename)


def test_published_imports_group_into_capabilities_without_a_second_parse(benign):
    published = _static(benign)["pe"]["imports"]

    assert sorted(published) == sorted(expected_imports())
    # kernel32 + user32 with two APIs each is an ordinary image: no capability claim.
    assert group_imports(published) == {}

    with_injection = published + ["kernel32.dll:CreateRemoteThread", "wininet.dll:InternetOpenA"]
    groups = group_imports(with_injection)

    assert groups["process_injection"] == ["kernel32.dll:CreateRemoteThread"]
    assert groups["network_c2"] == ["wininet.dll:InternetOpenA"]
    assert capability_meta("process_injection") == ("defense-evasion", "T1055")


def test_a_suspicious_layout_reaches_the_published_packer_tokens(benign):
    rw_text = pe.set_section_flags(benign, 0, pe.EXECUTE | pe.READ | pe.WRITE)
    clean = _static(benign)
    dirty = _static(rw_text)

    assert clean["packers"] == []
    assert dirty["packers"] != []
    assert any(token.startswith("sign:") for token in dirty["packers"])


def test_packer_named_sections_are_published_as_tools(benign):
    packed = pe.rename_section(pe.rename_section(benign, 0, "UPX0"), 1, "UPX1")

    assert _static(packed)["packers"] == ["tool:UPX"]


def test_yara_key_is_omitted_by_default_and_a_list_when_the_ruleset_ran(benign, monkeypatch):
    """Absent means "not assessed", [] means "ran and found nothing". M8 renders them
    differently, and M5 only lifts a clean verdict's confidence for the second."""
    from m2_static.yara_scan import engine_available

    monkeypatch.delenv("TRAC_YARA_ENABLED", raising=False)
    monkeypatch.delenv("TRAC_YARA_RULES_DIR", raising=False)

    assert "yara_matches" not in _static(benign)

    if not engine_available():
        pytest.skip("yara-python is an optional native dependency")

    monkeypatch.setenv("TRAC_YARA_ENABLED", "1")
    result = _static(benign)

    assert isinstance(result["yara_matches"], list)
    assert all("rule" in match for match in result["yara_matches"])


def test_an_unparseable_image_is_reported_failed_not_empty():
    result = analyze_static(data=b"\x00" * 64, file_type="pe", filename="broken.exe")

    assert result["status"] == "failed"
    assert result["packers"] == []
    assert "pe" not in result or not result["pe"]


def test_the_published_static_section_passes_the_contract_gate(benign):
    document = {"static": _static(benign)}

    assert semantic_errors(document) == []


def test_interesting_strings_with_defanging_expansion_stay_within_max_length():
    """Ensure defanging IP/URL expansion cannot push string length past schema maxLength."""
    import jsonschema
    from m7_core.contract.loader import get_analysis_schema
    from m2_static.analyzer import _extract_strings_section, _MAX_STR_LEN

    # Construct a string of ~510 characters containing multiple IP-like tokens
    # When defanged (e.g. 6.0.0.0 -> 6[.]0[.]0[.]0), it expands well past 512 characters.
    prefix = b"A" * 300
    suffix = b" 6.0.0.0 " * 25 + b"\x00"
    payload = prefix + suffix

    sec = _extract_strings_section(payload)
    for s in sec["interesting"]:
        assert len(s) <= _MAX_STR_LEN
        assert not s.endswith("[.")
        assert not s.endswith("[")

    schema = get_analysis_schema()
    wrapper = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": "#/$defs/static"}
    jsonschema.validate(
        instance={"status": "done", "file_class": "pe", "entropy": 5.0, "packers": [], "strings": sec},
        schema=wrapper,
    )
