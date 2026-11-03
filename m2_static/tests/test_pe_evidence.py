"""Regression coverage for m2_static.pe_evidence: each finding must have a byte that causes it.

The benign image is the control. If a check fires on it, the check is describing how
compilers work rather than how malware works, and it is wrong.
"""
from __future__ import annotations

import pytest

from m2_static.pe_evidence import (
    IMPORT_CAPABILITY_GROUPS,
    capability_meta,
    collect_pe_evidence,
    container_indicators,
    describe,
    group_imports,
)
from m2_static.tests import pe_mutants as pe


INITIAL_IMAGE = pe.benign_pe()


@pytest.fixture(scope="module")
def benign():
    return pe.benign_pe()


# --- the control -----------------------------------------------------------


def test_benign_fixture_carries_no_structural_finding(benign):
    evidence = collect_pe_evidence(benign)

    assert evidence.parsed is True
    assert evidence.findings == []
    assert evidence.packers == []
    assert evidence.overlay_size == 0
    assert describe(evidence) == ()


def test_findings_payload_is_plain_json_ready_dicts(benign):
    mutated = pe.set_section_flags(benign, 0, pe.EXECUTE | pe.READ | pe.WRITE)

    for finding in collect_pe_evidence(mutated).findings_payload():
        assert set(finding) == {"code", "detail", "values"}
        assert isinstance(finding["code"], str) and finding["detail"]


# --- section permissions ---------------------------------------------------


def test_writable_and_executable_section_is_named_with_its_permissions(benign):
    mutated = pe.set_section_flags(benign, 0, pe.EXECUTE | pe.READ | pe.WRITE)

    evidence = collect_pe_evidence(mutated)

    assert evidence.has("SECTION_RWX")
    [finding] = [f for f in evidence.findings if f["code"] == "SECTION_RWX"]
    assert ".text" in finding["detail"]


def test_read_only_executable_section_is_not_a_finding(benign):
    mutated = pe.set_section_flags(benign, 0, pe.EXECUTE | pe.READ)

    assert not collect_pe_evidence(mutated).has("SECTION_RWX")


# --- entry point -----------------------------------------------------------


def test_entry_point_inside_a_writable_section_is_called_out(benign):
    mutated = pe.set_section_flags(benign, 0, pe.READ | pe.WRITE)

    evidence = collect_pe_evidence(mutated)

    assert evidence.has("ENTRYPOINT_IN_WRITABLE_SECTION")


def test_entry_point_outside_every_section_is_called_out(benign):
    mutated = pe.set_entry_point(benign, 0x99_0000)

    evidence = collect_pe_evidence(mutated)

    assert evidence.has("ENTRYPOINT_OUTSIDE_SECTIONS")
    assert not evidence.has("ENTRYPOINT_IN_WRITABLE_SECTION")


# --- overlay ---------------------------------------------------------------


def test_bytes_after_the_last_section_are_measured(benign):
    payload = pe.overlay_payload(4096)
    evidence = collect_pe_evidence(pe.append_overlay(benign, payload))

    assert evidence.overlay_size == 4096
    assert evidence.has("OVERLAY_DATA")
    assert "sign:overlay_data" in evidence.packers


def test_a_short_tail_is_not_reported_as_overlay(benign):
    evidence = collect_pe_evidence(pe.append_overlay(benign, b"\x00\x00"))

    assert not evidence.has("OVERLAY_DATA")


# --- packer indicators -----------------------------------------------------


def test_a_packer_section_name_becomes_a_tool_token(benign):
    mutated = pe.rename_section(benign, 0, "UPX0")

    evidence = collect_pe_evidence(mutated)

    assert "tool:UPX" in evidence.packers
    assert evidence.has("PACKER_TOOL_SIGNATURE")


def test_an_executable_section_without_a_linker_name_is_reported_without_naming_a_tool(benign):
    mutated = pe.rename_section(benign, 0, "WEIRD")
    mutated = pe.set_section_flags(mutated, 0, pe.EXECUTE | pe.READ | pe.CODE)

    evidence = collect_pe_evidence(mutated)

    assert "anomalous_section:WEIRD" in evidence.packers
    assert not any(token.startswith("tool:") for token in evidence.packers)


def test_upx_banner_in_a_non_pe_container_is_still_attributed():
    assert container_indicators(b"prefix UPX! suffix") == ["tool:UPX"]


def test_a_non_pe_container_says_nothing_about_sections(benign):
    assert container_indicators(benign) == []


# --- mitigation flags ------------------------------------------------------


def test_missing_aslr_and_nx_are_reported_but_are_linker_choices(benign):
    evidence = collect_pe_evidence(pe.set_dll_characteristics(benign, 0))

    assert evidence.has("NO_ASLR")
    assert evidence.has("NO_NX_COMPAT")
    assert "PE_NO_ASLR" not in describe(evidence)


# --- unreadable input ------------------------------------------------------


def test_a_non_pe_image_is_read_as_absence_not_as_an_error():
    evidence = collect_pe_evidence(b"this is a shell script, not a PE")

    assert evidence.parsed is False
    assert evidence.findings == []


@pytest.mark.parametrize("cut", [2, 128, 300, 512])
def test_a_truncated_header_never_raises(benign, cut):
    evidence = collect_pe_evidence(benign[:cut])

    assert isinstance(evidence.findings, list)
    assert isinstance(evidence.packers, list)


# --- import capability grouping -------------------------------------------


def test_grouping_is_a_pure_function_over_the_published_import_list():
    groups = group_imports([
        "kernel32.dll:CreateRemoteThread",
        "advapi32.dll:RegSetValueExW",
        "wininet.dll:InternetOpenA",
        "kernel32.dll:GetVersion",
    ])

    assert groups["process_injection"] == ["kernel32.dll:CreateRemoteThread"]
    assert groups["persistence"] == ["advapi32.dll:RegSetValueExW"]
    assert groups["network_c2"] == ["wininet.dll:InternetOpenA"]
    assert "kernel32.dll:GetVersion" not in sum(groups.values(), [])


def test_an_ordinary_import_is_not_promoted_into_a_capability():
    assert group_imports(["kernel32.dll:ExitProcess", "user32.dll:MessageBoxA"]) == {}


def test_every_group_declares_either_a_technique_or_nothing():
    """A group without an ATT&CK id is descriptive, and must not be accused of a tactic."""

    with_technique = {(group, tactic, attack) for group, tactic, attack, _n in IMPORT_CAPABILITY_GROUPS
                      if attack}
    descriptive = {group for group, tactic, attack, _n in IMPORT_CAPABILITY_GROUPS if not attack}

    for group, tactic, attack in with_technique:
        assert capability_meta(group) == (tactic, attack)
    for group in descriptive:
        assert capability_meta(group) == (None, None)
    assert descriptive == {"cryptography", "file_io"}


def test_capability_meta_for_an_unknown_group_is_a_blank_not_a_guess():
    assert capability_meta("nonsense") == (None, None)


def test_the_benign_fixture_imports_no_capability():
    evidence = collect_pe_evidence(b"")

    assert evidence.import_groups == {}
