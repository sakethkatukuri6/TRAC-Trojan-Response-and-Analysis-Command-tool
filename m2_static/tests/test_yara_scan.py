"""Regression coverage for the opt-in local YARA path.

Two things matter here and they are easy to get wrong in opposite directions:
the engine must never be able to reach a rule the operator did not curate, and a
result that says "nothing matched" must be distinguishable from one that says
"nothing ran".
"""
from __future__ import annotations

import textwrap

import pytest

from m2_static import yara_scan
from m2_static.yara_scan import (
    ALLOWED_SUFFIXES,
    BUILTIN_RULES_DIR,
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_NO_RULES,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    asserts_malicious,
    engine_available,
    family_assertion,
    is_enabled,
    rule_files,
    rules_dir,
    scan,
    timeout_s,
)

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

requires_yara = pytest.mark.skipif(not engine_available(),
                                   reason="yara-python is an optional native dependency")


# --- opt-in wiring ---------------------------------------------------------


def test_the_engine_is_off_until_an_operator_turns_it_on():
    assert is_enabled({}) is False
    assert is_enabled({"TRAC_YARA_ENABLED": "0"}) is False
    assert is_enabled({"TRAC_YARA_ENABLED": ""}) is False
    assert is_enabled({"TRAC_YARA_ENABLED": "true"}) is True
    assert is_enabled({"TRAC_YARA_ENABLED": "YES"}) is True


def test_naming_a_rules_directory_is_itself_an_opt_in():
    assert is_enabled({"TRAC_YARA_RULES_DIR": "/tmp/myrules"}) is True


def test_disabled_scan_publishes_nothing():
    result = scan(b"any bytes", environ={})

    assert result.status == STATUS_DISABLED
    assert result.published() is None
    assert result.ran is False


def test_an_enabled_engine_with_no_rules_says_so_instead_of_claiming_a_clean_pass(tmp_path):
    result = scan(b"any bytes", environ={"TRAC_YARA_RULES_DIR": str(tmp_path)})

    assert result.status == STATUS_NO_RULES
    assert result.published() is None


# --- rule sourcing is restricted ------------------------------------------


def test_only_rule_suffixes_are_collected(tmp_path):
    (tmp_path / "one.yar").write_text("rule A { condition: false }", encoding="utf-8")
    (tmp_path / "two.yara").write_text("rule B { condition: false }", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("rule C { condition: false }", encoding="utf-8")
    (tmp_path / "payload.exe").write_bytes(b"MZ\x90\x00")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "three.yar").write_text("rule D { condition: false }", encoding="utf-8")

    names = sorted(path.name for path in rule_files(environ={"TRAC_YARA_RULES_DIR": str(tmp_path)}))

    assert names == ["one.yar", "three.yar", "two.yara"]
    assert ALLOWED_SUFFIXES == {".yar", ".yara"}


def test_an_oversized_rule_file_is_skipped_not_compiled(tmp_path):
    (tmp_path / "small.yar").write_text("rule A { condition: false }", encoding="utf-8")
    (tmp_path / "huge.yar").write_bytes(b"r" * (yara_scan.MAX_RULE_BYTES + 1))

    names = [path.name for path in rule_files(environ={"TRAC_YARA_RULES_DIR": str(tmp_path)})]

    assert names == ["small.yar"]


def test_a_missing_or_file_named_rules_directory_yields_no_rules(tmp_path):
    assert rule_files(tmp_path / "absent") == []
    a_file = tmp_path / "not-a-directory.yar"
    a_file.write_text("rule A { condition: false }", encoding="utf-8")
    assert rule_files(a_file) == []


def test_the_default_rules_directory_is_the_one_in_this_repository(tmp_path):
    assert rules_dir({}) == BUILTIN_RULES_DIR
    assert rules_dir({"TRAC_YARA_RULES_DIR": str(tmp_path)}) == tmp_path


# --- timeout is read but never trusted ------------------------------------


def test_timeout_falls_back_when_the_value_is_not_a_duration():
    assert timeout_s({}) == yara_scan.DEFAULT_TIMEOUT_S
    assert timeout_s({"TRAC_YARA_TIMEOUT_S": "not-a-number"}) == yara_scan.DEFAULT_TIMEOUT_S
    assert timeout_s({"TRAC_YARA_TIMEOUT_S": "-1"}) == yara_scan.DEFAULT_TIMEOUT_S
    assert timeout_s({"TRAC_YARA_TIMEOUT_S": "2.5"}) == 2.5


# --- what a match may and may not claim -----------------------------------


def test_a_declared_verdict_needs_an_explicit_statement():
    assert asserts_malicious({"rule": "R", "tags": ["malicious"]}) is True
    assert asserts_malicious({"rule": "R", "meta": {"verdict": "Malicious"}}) is True
    assert asserts_malicious({"rule": "R", "meta": {"malicious": "true"}}) is True
    assert asserts_malicious({"rule": "R", "tags": ["packer"], "meta": {"verdict": "info"}}) is False
    assert asserts_malicious({"rule": "R"}) is False


def test_a_rule_name_is_never_read_as_a_family():
    assert family_assertion([{"rule": "Win32_Trojan_AsyncRAT", "tags": ["malicious"]}]) is None
    assert family_assertion([{"rule": "R", "meta": {"description": "looks like agent tesla"}}]) is None
    assert family_assertion([{"rule": "R", "meta": {"family": "AsyncRAT"}}]) == "AsyncRAT"


# --- the shipped ruleset ---------------------------------------------------


@requires_yara
def test_the_repository_ruleset_compiles():
    files = rule_files()
    names = {path.stem for path in files}

    assert {"trac_eicar_test_file", "trac_pe_packers", "trac_example_declared_verdict"} <= names
    result = scan(b"MZ\x00\x00", environ={"TRAC_YARA_ENABLED": "1"})
    assert result.status == STATUS_OK, result.detail
    assert result.published() == []


@requires_yara
def test_the_eicar_rule_reports_the_test_file_with_its_own_metadata():
    result = scan(EICAR, environ={"TRAC_YARA_ENABLED": "1"})

    [match] = result.published()
    assert match["rule"] == "TRAC_EICAR_Anti_Malware_Test_File"
    assert match["meta"]["verdict"] == "info"
    assert "test_signature" in match["tags"]
    # The EICAR string is a test artefact; a rule that matches it must not threaten.
    assert asserts_malicious(match) is False
    assert family_assertion(result.published()) is None


@requires_yara
def test_a_declared_verdict_rule_is_the_only_kind_that_may_move_a_score():
    result = scan(b"TRAC-DEMO-SIGNATURE-DECLARED-MALICIOUS", environ={"TRAC_YARA_ENABLED": "1"})

    matches = result.published()
    assert matches and all(asserts_malicious(m) for m in matches)
    # Declaring a verdict is not declaring a family.
    assert family_assertion(matches) is None


@requires_yara
def test_a_packer_container_is_identified_as_a_tool_not_as_a_threat(benign_pe_bytes):
    from m2_static.tests import pe_mutants

    # The rule asks for UPX's own banner or the pair of section names it writes, so
    # one renamed section is not enough to make a tool claim.
    single = pe_mutants.rename_section(benign_pe_bytes, 0, "UPX0")
    packed = pe_mutants.rename_section(single, 1, "UPX1")

    assert scan(single, environ={"TRAC_YARA_ENABLED": "1"}).published() == []

    matches = scan(packed, environ={"TRAC_YARA_ENABLED": "1"}).published()
    assert [m["rule"] for m in matches] == ["TRAC_PE_Packed_UPX"]
    assert matches[0]["meta"]["verdict"] == "info"
    assert all(asserts_malicious(m) is False for m in matches)


@requires_yara
def test_a_broken_rule_reports_an_error_rather_than_an_empty_clean_result(tmp_path):
    (tmp_path / "broken.yar").write_text(textwrap.dedent("""
        rule NotARule
    """), encoding="utf-8")

    result = scan(b"anything", environ={"TRAC_YARA_RULES_DIR": str(tmp_path)})

    assert result.status == STATUS_ERROR
    assert result.published() is None
    assert result.detail


@requires_yara
def test_include_is_refused_so_a_rule_cannot_reach_outside_the_curated_directory(tmp_path):
    (tmp_path / "outside.yar").write_text('rule Secret { strings: $a = "x" condition: $a }',
                                          encoding="utf-8")
    (tmp_path / "main.yar").write_text('include "outside.yar"\nrule Main { condition: false }',
                                       encoding="utf-8")

    result = scan(b"xyz", environ={"TRAC_YARA_RULES_DIR": str(tmp_path)})

    assert result.status == STATUS_ERROR
    assert result.published() is None


@pytest.fixture
def benign_pe_bytes():
    from m7_core.tests.benign_pe import build_benign_pe

    return build_benign_pe()
