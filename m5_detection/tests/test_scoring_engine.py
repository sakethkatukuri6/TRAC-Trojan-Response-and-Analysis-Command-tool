import hashlib
import json
import struct
from typing import Callable, Dict, List, Tuple

import pytest

from m2_static import pe_evidence
from m2_static.analyzer import analyze_static
from m5_detection.scoring_engine import (
    ENTROPY_ELEVATED_POINTS,
    FACTOR_MAX_POINTS,
    MAX_STRUCTURAL_DETECTIONS,
    SCORE_MODEL_VERSION,
    STRUCTURAL_POINTS,
    STRUCTURAL_REPORT_ONLY,
    allocate_components,
    derive_confidence,
    evaluate_evidence,
    score_analysis,
)
from m7_core.tests.benign_pe import build_benign_pe

_SCORING_SECTIONS = ("score", "verdict", "detections")


def _score(data=b"ordinary", *, entropy=1.0, packers=(), capabilities=(), clamav="not_run",
            dynamic_status="skipped", yara=None):
    static = {"entropy": entropy, "packers": list(packers)}
    if yara is not None:
        static["yara_matches"] = yara
    dynamic = {"status": dynamic_status, "_static_capabilities": {c: {"matches": ["x"]} for c in capabilities}}
    return score_analysis(data, static, dynamic, {}, {"clamav_result": clamav})


def _evaluate(data=b"ordinary", *, entropy=1.0, packers=(), capabilities=(), clamav="not_run",
              dynamic_status="skipped", yara=None, static_status=None, file_class=None,
              imports=(), sha256=""):
    """The same inputs as ``_score``, but returning the claim ledger as well."""
    static: Dict[str, object] = {"entropy": entropy, "packers": list(packers)}
    if static_status is not None:
        static["status"] = static_status
    if file_class is not None:
        static["file_class"] = file_class
        static["pe"] = {"imports": list(imports)}
    if yara is not None:
        static["yara_matches"] = yara
    dynamic = {"status": dynamic_status, "_static_capabilities": {c: {"matches": ["x"]} for c in capabilities}}
    record: Dict[str, str] = {"clamav_result": clamav}
    if sha256:
        record["sha256"] = sha256
    return evaluate_evidence(data, static, dynamic, {}, record)


def test_score_has_no_hidden_baseline_or_fabricated_intel_hit():
    result = _score()

    assert result["score"]["value"] == 0
    assert sum(item["contribution"] for item in result["score"]["components"]) == 0
    # No reputation provider is queried, so the section must not claim an empty result set.
    assert "intel_hits" not in result["detections"]


def test_reported_weights_are_the_ceilings_the_score_is_built_from():
    result = _score(entropy=7.5, capabilities=["injection", "c2_networking"])
    by_name = {c["name"]: c for c in result["score"]["components"]}

    for name, ceiling in FACTOR_MAX_POINTS.items():
        assert by_name[name]["weight"] == ceiling / 100.0
    assert by_name["process_injection"]["contribution"] == FACTOR_MAX_POINTS["process_injection"]
    assert sum(c["contribution"] for c in result["score"]["components"]) == result["score"]["value"]


def test_no_factor_contribution_exceeds_its_declared_weight():
    result = _score(entropy=7.9, capabilities=["injection", "c2_networking", "persistence",
                                                "evasion", "keylogging"], clamav="detected")

    for component in result["score"]["components"]:
        assert component["contribution"] <= component["weight"] * 100.0 + 1e-9
    assert result["score"]["value"] == 100.0


def test_over_subscribed_factors_share_the_budget_so_components_sum_to_the_score():
    # 18 + 20 + 18 + 12 + 10 + 10 + 88 + 88 = 264 points of evidence against a 100-point scale.
    # Factors with no evidence keep a component of 0.0, so the published list still names
    # every factor the model can credit.
    result = _score(entropy=7.9, capabilities=["injection", "c2_networking", "persistence",
                                                "evasion", "keylogging"], clamav="detected")
    components = result["score"]["components"]

    assert sum(c["contribution"] for c in components) == 100.0
    assert [c["contribution"] for c in components] == [10.2, 11.4, 10.2, 6.8, 5.7, 5.7,
                                                       0.0, 0.0, 0.0, 50.0, 0.0]
    assert result["verdict"]["label"] == "malicious"


def test_overloaded_score_clears_the_contract_semantic_gate():
    from contract.tools.validate import semantic_errors

    result = _score(entropy=7.9, capabilities=["injection", "c2_networking", "persistence",
                                                "evasion", "keylogging"], clamav="detected")
    doc = {"score": result["score"], "verdict": result["verdict"], "detections": result["detections"]}

    assert semantic_errors(doc) == []


def test_factor_points_are_unchanged_by_making_the_weights_operative():
    assert _score(entropy=7.2)["score"]["value"] == FACTOR_MAX_POINTS["entropy_heuristics"]
    assert _score(entropy=6.5)["score"]["value"] == ENTROPY_ELEVATED_POINTS
    assert _score(capabilities=["injection"])["score"]["value"] == FACTOR_MAX_POINTS["process_injection"]
    assert _score(capabilities=["c2_networking"])["score"]["value"] == FACTOR_MAX_POINTS["c2_network_activity"]
    assert _score(capabilities=["persistence"])["score"]["value"] == FACTOR_MAX_POINTS["persistence_routines"]
    assert _score(capabilities=["evasion"])["score"]["value"] == FACTOR_MAX_POINTS["evasion_techniques"]
    assert _score(capabilities=["keylogging"])["score"]["value"] == FACTOR_MAX_POINTS["surveillance_modules"]
    assert _score(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", entropy=1.0)["score"]["value"] == FACTOR_MAX_POINTS["signature_match"]


def test_confidence_follows_evidence_not_the_score_band():
    # Same 68-point score, different evidence base.
    heuristic_only = _score(entropy=7.2, capabilities=["injection", "c2_networking", "persistence"])
    corroborated = _score(entropy=7.2, capabilities=["injection", "c2_networking", "persistence"], yara=[])

    assert heuristic_only["score"]["value"] == corroborated["score"]["value"] == 68.0
    assert heuristic_only["verdict"]["label"] == corroborated["verdict"]["label"] == "malicious"
    assert heuristic_only["verdict"]["confidence"] == 0.6
    assert corroborated["verdict"]["confidence"] == 0.8


def test_benign_confidence_states_how_little_was_ruled_out():
    unscanned = _score()
    scanned = _score(clamav="clean", yara=[])

    assert unscanned["verdict"]["label"] == scanned["verdict"]["label"] == "benign"
    assert unscanned["verdict"]["confidence"] == 0.3
    assert scanned["verdict"]["confidence"] == 0.6
    assert "no corroborating engine ran" in unscanned["verdict"]["explanation"][-1]
    assert "ClamAV and YARA rules" in scanned["verdict"]["explanation"][-1]


def test_sandbox_telemetry_alone_lifts_confidence():
    result = _score(entropy=7.2, capabilities=["injection"], dynamic_status="done")

    assert result["verdict"]["confidence"] == 0.8
    assert "sandbox telemetry" in result["verdict"]["explanation"][-1]


def test_derive_confidence_requires_both_scanners_for_a_clean_claim():
    assert derive_confidence("benign", signature_hit=False, av_ran=True, yara_ran=False,
                             runtime_observed=False) == 0.3
    assert derive_confidence("benign", signature_hit=False, av_ran=False, yara_ran=True,
                             runtime_observed=False) == 0.3
    assert derive_confidence("benign", signature_hit=False, av_ran=True, yara_ran=True,
                             runtime_observed=False) == 0.6


def test_benign_still_explains_itself():
    result = _score()

    assert "File analyzed without actionable malicious indicators." in result["verdict"]["explanation"]


def test_verdict_bands_start_where_the_contract_ceiling_ends():
    from contract.tools.validate import semantic_errors

    at_benign_ceiling = _score(entropy=7.2, capabilities=["persistence"])          # 18 + 12
    just_above_it = _score(entropy=7.2, capabilities=["persistence", "evasion"])   # 18 + 12 + 10
    at_malicious_floor = _score(capabilities=["injection", "c2_networking", "persistence", "evasion"])

    assert at_benign_ceiling["score"]["value"] == 30.0
    assert at_benign_ceiling["verdict"]["label"] == "benign"
    assert just_above_it["verdict"]["label"] == "suspicious"
    assert at_malicious_floor["score"]["value"] == 60.0
    assert at_malicious_floor["verdict"]["label"] == "malicious"
    assert at_malicious_floor["verdict"]["severity"] == "high"

    for result in (at_benign_ceiling, just_above_it, at_malicious_floor):
        doc = {"score": result["score"], "verdict": result["verdict"], "detections": result["detections"]}
        assert semantic_errors(doc) == []


def _corpus(tmp_path, monkeypatch, entries, provider="malwarebazaar"):
    path = tmp_path / "known_bad.json"
    path.write_text('{"provider": "%s", "updated_at": "2026-10-31", "entries": %s}'
                    % (provider, __import__("json").dumps(entries)), encoding="utf-8")
    monkeypatch.setenv("TRAC_KNOWN_BAD_DB", str(path))


def test_a_reputation_hit_drives_the_verdict_when_static_heuristics_see_nothing(tmp_path, monkeypatch):
    digest = "f" * 64
    _corpus(tmp_path, monkeypatch, [{"sha256": digest, "result": "known_malicious", "family": "Valley RAT"}])
    result = score_analysis(
        b"opaque binary",
        {"entropy": 6.2, "packers": []},
        {"status": "skipped", "_static_capabilities": {}},
        {},
        {"clamav_result": "not_run", "sha256": digest},
    )

    assert result["score"]["value"] == FACTOR_MAX_POINTS["threat_intel_match"]
    assert result["verdict"]["label"] == "malicious"
    assert result["verdict"]["severity"] == "critical"
    assert result["verdict"]["confidence"] == 0.9
    assert result["verdict"]["family_guess"] == "valley_rat"
    hit = result["detections"]["intel_hits"][0]
    assert hit == {"provider": "malwarebazaar", "indicator": digest,
                   "result": "known_malicious", "cached": True}
    assert [i["kind"] for i in result["detections"]["items"]] == ["intel"]


def test_an_absent_corpus_is_not_read_as_a_clean_bill(tmp_path, monkeypatch):
    monkeypatch.setenv("TRAC_KNOWN_BAD_DB", str(tmp_path / "does_not_exist.json"))
    result = _score()

    assert result["score"]["value"] == 0
    assert "intel_hits" not in result["detections"]
    assert result["verdict"]["confidence"] == 0.3


def test_a_malformed_corpus_is_ignored_rather_than_defaulting(tmp_path, monkeypatch):
    path = tmp_path / "known_bad.json"
    path.write_text("{ not json", encoding="utf-8")
    monkeypatch.setenv("TRAC_KNOWN_BAD_DB", str(path))
    result = score_analysis(b"x", {"entropy": 1.0, "packers": []}, {"status": "skipped"}, {},
                           {"sha256": "a" * 64})

    assert "intel_hits" not in result["detections"]
    assert result["verdict"]["label"] == "benign"


def test_a_known_clean_entry_does_not_add_threat_points(tmp_path, monkeypatch):
    digest = "b" * 64
    _corpus(tmp_path, monkeypatch, [{"sha256": digest, "result": "known_clean"}])
    result = score_analysis(b"x", {"entropy": 1.0, "packers": []}, {"status": "skipped"}, {},
                           {"sha256": digest})

    assert result["score"]["value"] == 0
    assert result["detections"]["intel_hits"] == [
        {"provider": "malwarebazaar", "indicator": digest, "result": "known_clean", "cached": True}
    ]


def test_the_shipped_corpus_is_tracked_not_gitignored(tmp_path, monkeypatch):
    monkeypatch.delenv("TRAC_KNOWN_BAD_DB", raising=False)
    from m5_detection.intel import DEFAULT_DB_PATH, corpus_provider, lookup_known_bad

    assert DEFAULT_DB_PATH.exists(), f"{DEFAULT_DB_PATH} is missing from the tree"
    assert corpus_provider() == "malwarebazaar"
    shipped = [e["sha256"] for e in json.loads(DEFAULT_DB_PATH.read_text(encoding="utf-8"))["entries"]]
    for digest in shipped:
        assert lookup_known_bad(digest) is not None


# ---------------------------------------------------------------------------
# PE fixtures: real images M2 can parse, with known structural evidence
# ---------------------------------------------------------------------------

SECTION_HEADER_SIZE = 40
SECTION_CHARACTERISTICS_OFFSET = 36
IMAGE_SCN_MEM_WRITE = 0x80000000
# The benign fixture lays its first section down at SIZE_OF_HEADERS (0x400) with a
# 512-byte raw size, and this block is 512 bytes of every possible byte value, so
# the section reads as 8.0 bits/byte: nothing plaintext about it.
SIZE_OF_HEADERS = 0x400
MAX_ENTROPY_BLOCK = bytes(range(256)) * 2


def _pe_layout(data: bytes) -> Dict[str, int]:
    """Offsets of the optional-header fields the fixtures poke."""
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe_offset + 4
    size_of_optional_header = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    return {
        "section_count": coff + 2,
        "optional": optional,
        "entry_point": optional + 16,
        "size_of_image": optional + 56,
        "dll_characteristics": optional + 70,
        "sections": optional + size_of_optional_header,
    }


def _poke(data: bytes, offset: int, value: int, fmt: str = "<I") -> bytes:
    image = bytearray(data)
    struct.pack_into(fmt, image, offset, value)
    return bytes(image)


def _make_section_writable(data: bytes, index: int = 0) -> bytes:
    layout = _pe_layout(data)
    offset = layout["sections"] + index * SECTION_HEADER_SIZE + SECTION_CHARACTERISTICS_OFFSET
    characteristics = struct.unpack_from("<I", data, offset)[0]
    return _poke(data, offset, characteristics | IMAGE_SCN_MEM_WRITE)


def _make_section_unprotectionless(data: bytes) -> bytes:
    """Clear DYNAMIC_BASE and NX_COMPAT, so the two report-only findings fire."""
    return _poke(data, _pe_layout(data)["dll_characteristics"], 0x0000, "<H")


def _rwx_text_pe() -> bytes:
    """The benign image with its code section marked writable: two findings, both cheap."""
    return _make_section_writable(build_benign_pe())


def _high_entropy_text(data: bytes) -> bytes:
    image = bytearray(data)
    image[SIZE_OF_HEADERS:SIZE_OF_HEADERS + len(MAX_ENTROPY_BLOCK)] = MAX_ENTROPY_BLOCK
    return bytes(image)


def _appended(data: bytes, size: int = 2048, banner: bytes = b"") -> bytes:
    """Bytes past the last section, which is overlay by definition."""
    return data + (MAX_ENTROPY_BLOCK * (size // len(MAX_ENTROPY_BLOCK))) + banner


def _report_only_pe() -> bytes:
    """A parsed image carrying both scoring and report-only structural findings."""
    image = _make_section_writable(build_benign_pe())
    image = _high_entropy_text(image)
    image = _make_section_unprotectionless(image)
    return _appended(image, 2048, b"UPX!")


def _many_section_pe() -> bytes:
    """The benign image plus four writable, oddly named sections.

    Every extra section raises its own findings, so the header reports more than
    ``MAX_STRUCTURAL_DETECTIONS`` of them.
    """
    data = build_benign_pe()
    layout = _pe_layout(data)
    existing = struct.unpack_from("<H", data, layout["section_count"])[0]
    extra = [("RXA0", 0x3000, 0x800), ("RXA1", 0x4000, 0xA00),
             ("RXA2", 0x5000, 0xC00), ("RXA3", 0x6000, 0xE00)]

    image = bytearray(data)
    struct.pack_into("<H", image, layout["section_count"], existing + len(extra))
    for index, (name, rva, pointer) in enumerate(extra):
        start = layout["sections"] + (existing + index) * SECTION_HEADER_SIZE
        image[start:start + SECTION_HEADER_SIZE] = struct.pack(
            "<8sIIIIIIHHI", name.encode(), len(MAX_ENTROPY_BLOCK), rva,
            len(MAX_ENTROPY_BLOCK), pointer, 0, 0, 0, 0, 0xE0000020)
    struct.pack_into("<I", image, layout["size_of_image"], 0x8000)
    image += bytes(0x1000 - len(image))
    for index, (_name, _rva, pointer) in enumerate(extra):
        image[pointer:pointer + len(MAX_ENTROPY_BLOCK)] = (
            MAX_ENTROPY_BLOCK if index % 2 == 0 else bytes(len(MAX_ENTROPY_BLOCK)))
    data = _make_section_unprotectionless(bytes(image))
    return _appended(data, 512, b"UPX!")


def _static_for(data: bytes, name: str = "sample.exe") -> Dict[str, object]:
    """M2's real output for these bytes, so the M2 -> M5 path is the one under test."""
    return analyze_static(data, "pe", name)


def _semantics(document: Dict[str, object]) -> List[str]:
    from contract.tools.validate import semantic_errors

    return semantic_errors({section: document[section] for section in _SCORING_SECTIONS})


def _claimed_by_factor(evaluation) -> Dict[str, float]:
    totals: Dict[str, float] = {}
    for contribution in evaluation.contributions:
        totals[contribution.factor] = totals.get(contribution.factor, 0.0) + contribution.points
    return totals


def _published(document: Dict[str, object]) -> Dict[str, float]:
    return {c["name"]: c["contribution"] for c in document["score"]["components"]}


def _assert_score_is_the_ledger(evaluation) -> Dict[str, float]:
    """The module's one rule, checked end to end: no term without a detection item.

    The ledger is the only input ``allocate_components`` is allowed to have produced
    these components from, so recomputing the score from the claims must reproduce
    the published document exactly.
    """
    document = evaluation.document
    published_items = {item["rule_id"] for item in document["detections"]["items"]}
    totals = _claimed_by_factor(evaluation)

    for contribution in evaluation.contributions:
        assert contribution.factor in FACTOR_MAX_POINTS, contribution
        assert contribution.points > 0.0, contribution
        assert contribution.evidence, f"{contribution.rule_id} scores without citing evidence"
        assert contribution.rule_id in published_items, (
            f"{contribution.rule_id} moves the score but is not in detections.items")

    # The factors that claimed points are precisely the ones that contribute.
    assert {name for name, points in totals.items() if points} == {
        name for name, value in _published(document).items() if value}
    # ... and the published numbers are the allocation of those claims, unchanged.
    assert totals == {name: points for name, points in evaluation.points.items() if points}
    recomputed_score, recomputed = allocate_components(totals)
    assert recomputed_score == document["score"]["value"]
    assert {c["name"]: c["contribution"] for c in recomputed if c["contribution"]} == {
        name: value for name, value in _published(document).items() if value}
    return totals


# ---------------------------------------------------------------------------
# 1. Traceability
# ---------------------------------------------------------------------------


def test_over_subscribed_score_is_recomputable_from_the_claim_ledger():
    evaluation = _evaluate(
        b"opaque payload", entropy=7.9, packers=["tool:UPX", "sign:overlay_data"],
        capabilities=["injection", "c2_networking", "persistence", "evasion", "keylogging",
                      "credentials", "screen_capture", "service_control"],
        clamav="detected", dynamic_status="done")
    document = evaluation.document
    totals = _assert_score_is_the_ledger(evaluation)

    # 18 + 12 + 20 + 18 + 12 + 10 + 10 + 16 + 88 = 184 points of evidence, 100 of scale.
    assert sum(totals.values()) > 100.0
    assert document["score"]["value"] == 100.0
    assert [c["contribution"] for c in document["score"]["components"] if c["contribution"]] == [
        8.8, 9.8, 8.8, 5.9, 4.9, 4.9, 5.9, 7.8, 43.2]
    assert round(sum(_published(document).values()), 2) == 100.0
    assert _semantics(document) == []


def test_advanced_capabilities_are_credited_once_per_technique():
    evaluation = _evaluate(capabilities=["keylogging", "input_capture", "credentials"])
    _assert_score_is_the_ledger(evaluation)

    # Keylogging already spent T1056.001, so input_capture is the same evidence twice.
    assert [c.rule_id for c in evaluation.contributions
            if c.factor == "advanced_capabilities"] == ["CAPABILITY_CREDENTIALS"]


def test_a_capability_named_only_by_the_import_table_still_leaves_a_trail():
    evaluation = _evaluate(static_status="done", file_class="pe",
                           imports=["advapi32.dll:OpenServiceA", "mpr.dll:WNetAddConnection2"])
    totals = _assert_score_is_the_ledger(evaluation)

    # ``group_imports`` publishes its groups in name order, and the claims follow it.
    assert [c.rule_id for c in evaluation.contributions] == [
        "CAPABILITY_LATERAL_MOVEMENT", "CAPABILITY_SERVICE_CONTROL"]
    assert totals == {"advanced_capabilities": 16.0}
    assert evaluation.document["score"]["value"] == 16.0
    assert [item["rule_id"] for item in evaluation.document["detections"]["items"]] == [
        "CAPABILITY_LATERAL_MOVEMENT", "CAPABILITY_SERVICE_CONTROL"]
    assert _semantics(evaluation.document) == []


def test_pe_structural_anomalies_are_traceable_one_item_per_claimed_point():
    data = _rwx_text_pe()
    evaluation = evaluate_evidence(data, _static_for(data),
                                   {"status": "skipped", "_static_capabilities": {}}, {},
                                   {"clamav_result": "not_run"})
    totals = _assert_score_is_the_ledger(evaluation)

    # Nothing here is over the scale or over a ceiling, so each factor's claims are
    # the published contribution to the cent.
    assert totals == {"packing_indicators": 6.0, "structural_anomalies": 12.0}
    assert _published(evaluation.document) == {
        **{name: 0.0 for name in FACTOR_MAX_POINTS},
        "packing_indicators": 6.0,
        "structural_anomalies": 12.0,
    }
    assert [c.rule_id for c in evaluation.contributions] == [
        "PACKER_DETECTED", "PE_SECTION_RWX", "PE_ENTRYPOINT_IN_WRITABLE_SECTION"]
    assert evaluation.document["score"]["value"] == 18.0
    assert _semantics(evaluation.document) == []


def test_zero_evidence_sample_has_no_claims_no_items_and_no_components():
    evaluation = _evaluate()

    assert _assert_score_is_the_ledger(evaluation) == {}
    assert evaluation.contributions == []
    assert evaluation.document["detections"]["items"] == []
    assert set(_published(evaluation.document)) == set(FACTOR_MAX_POINTS)
    assert all(value == 0.0 for value in _published(evaluation.document).values())
    assert evaluation.document["score"]["value"] == 0.0


def test_score_analysis_publishes_exactly_what_evaluate_evidence_documents():
    data = _report_only_pe()
    static = _static_for(data)

    assert score_analysis(data, static, {"status": "skipped", "_static_capabilities": {}}, {},
                          {"clamav_result": "not_run"}) == evaluate_evidence(
        data, static, {"status": "skipped", "_static_capabilities": {}}, {},
        {"clamav_result": "not_run"}).document


# ---------------------------------------------------------------------------
# 2. Sums exactly, across the whole input spread
# ---------------------------------------------------------------------------


def _spread() -> List[Tuple[str, Callable[[], Tuple[bytes, dict, dict, dict, dict]]]]:
    def wrap(data, name="sample.exe", capabilities=(), clamav="not_run", dynamic_status="skipped"):
        def build():
            static = _static_for(data, name)
            dynamic = {"status": dynamic_status,
                       "_static_capabilities": {c: {"matches": ["x"]} for c in capabilities}}
            return data, static, dynamic, {}, {"clamav_result": clamav}
        return build

    benign = build_benign_pe()
    return [
        ("no evidence at all", lambda: (b"ordinary", {"entropy": 1.0, "packers": []},
                                        {"status": "skipped", "_static_capabilities": {}}, {},
                                        {"clamav_result": "not_run"})),
        ("elevated entropy only", lambda: (b"ordinary", {"entropy": 6.9, "packers": []},
                                           {"status": "skipped", "_static_capabilities": {}}, {},
                                           {"clamav_result": "clean"})),
        ("one behavioural factor", lambda: (b"ordinary", {"entropy": 1.0, "packers": []},
                                           {"status": "done", "_static_capabilities": {"injection": {
                                               "matches": ["kernel32.dll:WriteProcessMemory"]}}},
                                           {}, {"clamav_result": "not_run"})),
        ("benign PE as M2 read it", wrap(benign)),
        ("PE with a writable code section", wrap(_rwx_text_pe())),
        ("PE with mixed scoring and report-only findings", wrap(_report_only_pe())),
        ("PE with more findings than the cap keeps", wrap(_many_section_pe())),
        ("packed-looking PE that also trips a signature", wrap(_many_section_pe(),
                                                              capabilities=["injection", "persistence"],
                                                              clamav="detected")),
        ("EICAR bytes as submitted", lambda: (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
                                             {"entropy": 4.0, "packers": []},
                                             {"status": "skipped", "_static_capabilities": {}}, {},
                                             {"clamav_result": "not_run"})),
        ("unparseable image with heuristics still firing",
         lambda: (b"MZ but not a PE", {"status": "failed", "file_class": "pe", "pe": None,
                                      "entropy": 7.3, "packers": ["sign:overlay_data"]},
                  {"status": "skipped", "_static_capabilities": {}}, {},
                  {"clamav_result": "not_run"})),
    ]


@pytest.mark.parametrize("label, build_inputs", _spread(), ids=[case[0] for case in _spread()])
def test_components_sum_to_the_score_to_the_cent_for_every_shape(label, build_inputs):
    document = evaluate_evidence(*build_inputs()).document
    components = document["score"]["components"]
    total = sum(c["contribution"] for c in components)

    assert round(total, 2) == document["score"]["value"], label
    assert abs(total - document["score"]["value"]) < 1e-9, label
    assert document["score"]["model_version"] == SCORE_MODEL_VERSION


@pytest.mark.parametrize("label, build_inputs", _spread(), ids=[case[0] for case in _spread()])
def test_no_component_exceeds_its_declared_weight_and_the_gate_passes(label, build_inputs):
    document = evaluate_evidence(*build_inputs()).document

    for component in document["score"]["components"]:
        assert component["weight"] == FACTOR_MAX_POINTS[component["name"]] / 100.0
        assert component["contribution"] <= component["weight"] * 100.0 + 1e-9, component
        assert component["contribution"] >= 0.0, component
    assert document["score"]["value"] <= 100.0
    assert _semantics(document) == []


@pytest.mark.parametrize("label, build_inputs", _spread(), ids=[case[0] for case in _spread()])
def test_the_ledger_backs_the_published_score_for_every_shape(label, build_inputs):
    _assert_score_is_the_ledger(evaluate_evidence(*build_inputs()))


def test_the_real_m2_reading_of_a_benign_image_is_a_benign_score():
    data = build_benign_pe()
    static = _static_for(data)
    evaluation = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                   {}, {"clamav_result": "not_run"})

    # M2 genuinely parsed it, so this is a reading of "nothing unusual", not of "no reading".
    assert static["status"] == "done" and static["pe"]["imports"]
    assert static["packers"] == [] and static["entropy"] < 3.0
    assert evaluation.contributions == []
    assert evaluation.document["detections"]["items"] == []
    assert evaluation.document["score"]["value"] == 0.0
    assert evaluation.document["verdict"]["label"] == "benign"
    assert _semantics(evaluation.document) == []


def test_a_reputation_hit_is_one_claim_backing_one_item(tmp_path, monkeypatch):
    digest = "c" * 64
    _corpus(tmp_path, monkeypatch, [{"sha256": digest, "result": "known_malicious",
                                     "family": "Valley RAT"}])
    evaluation = evaluate_evidence(b"opaque", {"entropy": 1.0, "packers": []},
                                   {"status": "skipped", "_static_capabilities": {}}, {},
                                   {"clamav_result": "not_run", "sha256": digest})
    totals = _assert_score_is_the_ledger(evaluation)

    assert totals == {"threat_intel_match": FACTOR_MAX_POINTS["threat_intel_match"]}
    assert _published(evaluation.document)["threat_intel_match"] == 88.0
    assert evaluation.document["score"]["value"] == 88.0
    assert _semantics(evaluation.document) == []


# ---------------------------------------------------------------------------
# 3. Unknown stays unknown
# ---------------------------------------------------------------------------


def test_an_image_that_was_never_read_is_unknown_rather_than_benign():
    static = {"status": "failed", "file_class": "pe", "pe": None, "entropy": 7.6,
              "packers": ["sign:overlay_data"], "strings": {"count": 0, "interesting": []}}
    result = score_analysis(b"MZ-shaped junk", static, {"status": "skipped",
                                                        "_static_capabilities": {}}, {},
                            {"clamav_result": "not_run"})

    # Heuristics still score the bytes it could see, but a partial read cannot certify clean.
    assert result["score"]["value"] == 24.0
    assert result["verdict"]["label"] == "unknown"
    assert result["verdict"]["severity"] == "low"
    assert result["verdict"]["confidence"] == 0.2
    assert any("never read" in line for line in result["verdict"]["explanation"])
    assert "reported status 'failed'" in " ".join(result["verdict"]["explanation"])
    assert _semantics(result) == []


def test_a_clean_benign_score_from_a_failed_reading_is_still_not_called_benign():
    static = {"status": "failed", "file_class": "pe", "pe": None, "entropy": 1.0, "packers": []}
    result = score_analysis(b"MZ-shaped junk", static, {"status": "skipped",
                                                        "_static_capabilities": {}}, {},
                            {"clamav_result": "not_run"})

    assert result["score"]["value"] == 0.0
    assert result["verdict"]["label"] == "unknown"
    assert result["verdict"]["severity"] == "info"
    assert "an absent finding is not evidence of absence" in " ".join(result["verdict"]["explanation"])


def test_m2s_own_failure_path_reaches_m5_as_unknown():
    broken = _poke(build_benign_pe(), 0x3C, 0x7FFF)
    static = _static_for(broken)
    result = score_analysis(broken, static, {"status": "skipped", "_static_capabilities": {}}, {},
                            {"clamav_result": "not_run"})

    assert static["status"] == "failed"
    assert result["verdict"]["label"] == "unknown"
    assert result["verdict"]["confidence"] == 0.2


def test_a_signature_names_the_threat_even_when_the_image_cannot_be_read():
    static = {"status": "failed", "file_class": "pe", "pe": None, "entropy": 1.0, "packers": []}
    result = score_analysis(b"MZ-shaped junk", static, {"status": "skipped",
                                                         "_static_capabilities": {}}, {},
                            {"clamav_result": "detected"})

    assert result["verdict"]["label"] == "malicious"
    assert result["verdict"]["confidence"] == 0.95
    assert "never read" not in " ".join(result["verdict"]["explanation"])


def test_a_fully_parsed_benign_image_is_never_reported_as_unknown():
    data = build_benign_pe()
    static = dict(_static_for(data))
    static["yara_matches"] = []          # the ruleset ran and cleared the image
    result = score_analysis(data, static, {"status": "skipped", "_static_capabilities": {}}, {},
                            {"clamav_result": "clean"})

    assert static["status"] == "done"
    assert result["verdict"]["label"] == "benign"
    assert result["verdict"]["confidence"] == 0.6
    assert "never read" not in " ".join(result["verdict"]["explanation"])


# ---------------------------------------------------------------------------
# 4. A family name needs an engine that states one
# ---------------------------------------------------------------------------


def test_a_family_is_never_read_off_the_filename_or_the_payload_bytes(tmp_path, monkeypatch):
    # The corpus holds other families and not this digest: it asserts nothing about it.
    _corpus(tmp_path, monkeypatch, [{"sha256": "d" * 64, "result": "known_malicious",
                                     "family": "Valley RAT"}])
    data = build_benign_pe() + b"asyncrat"
    static = _static_for(data, "asyncrat.exe")
    evaluation = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                   {}, {"clamav_result": "clean",
                                       "sha256": hashlib.sha256(data).hexdigest(),
                                       "original_name": "asyncrat.exe", "filename": "asyncrat.exe"})
    document = evaluation.document

    assert b"asyncrat" in data and "asyncrat" in "asyncrat.exe"
    assert static["status"] == "done"
    assert "intel_hits" not in document["detections"]
    assert document["verdict"]["family_guess"] == "unknown"
    assert document["verdict"]["label"] == "benign"
    assert not any("asyncrat" in json.dumps(item).lower() for item in document["detections"]["items"])
    assert _semantics(document) == []


def test_a_yara_rule_name_is_not_a_family_declaration():
    data = build_benign_pe()
    static = dict(_static_for(data, "asyncrat.exe"))
    static["yara_matches"] = [{"rule": "Win32_AsyncRAT_Gen_1", "namespace": "repo",
                               "tags": ["trojan"], "meta": {"author": "TRAC"}}]
    evaluation = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                   {}, {"clamav_result": "not_run"})

    assert evaluation.document["verdict"]["family_guess"] == "unknown"
    # A matching rule that declares no verdict is evidence about the rule, not a threat.
    assert evaluation.contributions == []
    assert evaluation.document["score"]["value"] == 0.0
    item = evaluation.document["detections"]["items"][0]
    assert item["rule_id"] == "YARA_Win32_AsyncRAT_Gen_1" and item["severity"] == "info"


def test_only_meta_family_on_a_matched_rule_may_name_a_family():
    data = build_benign_pe()
    static = dict(_static_for(data))
    static["yara_matches"] = [{"rule": "Generic_Builder_Stringset", "namespace": "repo",
                               "tags": ["malicious"], "meta": {"family": "AsyncRAT"}}]
    evaluation = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                   {}, {"clamav_result": "not_run"})

    assert evaluation.document["verdict"]["family_guess"] == "asyncrat"
    assert _claimed_by_factor(evaluation) == {"signature_match": 88.0}
    assert _semantics(evaluation.document) == []


def test_a_corpus_entry_that_names_a_family_is_the_other_source(tmp_path, monkeypatch):
    digest = "e" * 64
    _corpus(tmp_path, monkeypatch, [{"sha256": digest, "result": "known_malicious",
                                     "family": "AsyncRAT"}])
    result = score_analysis(b"opaque", {"entropy": 1.0, "packers": []},
                            {"status": "skipped", "_static_capabilities": {}}, {},
                            {"clamav_result": "not_run", "sha256": digest})

    assert result["verdict"]["family_guess"] == "asyncrat"
    assert [item["rule_id"] for item in result["detections"]["items"]] == ["INTEL_HASH_KNOWN_BAD"]


# ---------------------------------------------------------------------------
# 5. Structural and packing evidence stays inside its ceiling
# ---------------------------------------------------------------------------


def test_a_wall_of_pe_findings_cannot_outrun_the_structural_ceiling():
    data = _many_section_pe()
    static = _static_for(data)
    evaluation = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                   {}, {"clamav_result": "not_run"})

    evidence = pe_evidence.collect_pe_evidence(data)
    assert len(evidence.findings) == 14 > MAX_STRUCTURAL_DETECTIONS
    published_structural = [item for item in evaluation.document["detections"]["items"]
                            if item["rule_id"].startswith("PE_")]
    scored_published = [item for item in published_structural if item["severity"] != "info"]
    # The cap is a limit on what may move the score. Report-only findings cost nothing,
    # so they stay in the report instead of being silently dropped by the ranking.
    assert len(scored_published) == MAX_STRUCTURAL_DETECTIONS
    assert len(published_structural) > MAX_STRUCTURAL_DETECTIONS

    claimed = _assert_score_is_the_ledger(evaluation)["structural_anomalies"]
    # The cap keeps the ten highest-value findings, and only those are credited.
    published_codes = [item["rule_id"][len("PE_"):] for item in scored_published]
    assert claimed == sum(STRUCTURAL_POINTS.get(code, 0.0) for code in published_codes) == 44.0
    assert published_codes.count("SECTION_RWX") == 4
    assert claimed > FACTOR_MAX_POINTS["structural_anomalies"]
    component = [c for c in evaluation.document["score"]["components"]
                 if c["name"] == "structural_anomalies"][0]
    assert component["contribution"] == FACTOR_MAX_POINTS["structural_anomalies"] == 14.0
    assert component["contribution"] <= component["weight"] * 100.0
    # Two capped factors cannot together report more than the two ceilings.
    assert evaluation.document["score"]["value"] == (
        FACTOR_MAX_POINTS["structural_anomalies"] + FACTOR_MAX_POINTS["packing_indicators"])
    assert _semantics(evaluation.document) == []


def test_report_only_findings_are_published_yet_score_nothing():
    data = _report_only_pe()
    static = _static_for(data)
    evaluation = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                   {}, {"clamav_result": "not_run"})
    items = {item["rule_id"]: item for item in evaluation.document["detections"]["items"]}
    rule_ids = {contribution.rule_id for contribution in evaluation.contributions}

    for code in STRUCTURAL_REPORT_ONLY:
        assert f"PE_{code}" in items, code
        assert items[f"PE_{code}"]["severity"] == "info"
        assert f"PE_{code}" not in rule_ids, code

    scoring = {c.rule_id: c.points for c in evaluation.contributions
               if c.factor == "structural_anomalies"}
    assert sum(scoring.values()) > FACTOR_MAX_POINTS["structural_anomalies"]
    assert all(STRUCTURAL_POINTS[rule[len("PE_"):]] > 0.0 for rule in scoring)
    assert _published(evaluation.document)["structural_anomalies"] == 14.0
    # The named tool is packing evidence, and packing evidence is credited only once.
    assert _claimed_by_factor(evaluation)["packing_indicators"] == 12.0
    assert _semantics(evaluation.document) == []


def test_a_rule_that_declares_no_verdict_cannot_name_a_family_either():
    # `meta.family` on a rule that only matched would attach a threat identification to
    # a verdict that scored nothing. Both claims travel together or not at all.
    data = build_benign_pe()
    static = dict(_static_for(data))
    static["yara_matches"] = [{"rule": "TRAC_PE_Packed_UPX", "namespace": "repo",
                              "tags": ["packer"], "meta": {"verdict": "info",
                                                           "family": "AsyncRAT"}}]
    evaluation = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                   {}, {"clamav_result": "not_run"})
    verdict = evaluation.document["verdict"]

    assert verdict["family_guess"] == "unknown"
    assert verdict["label"] == "benign"
    assert evaluation.points["signature_match"] == 0.0
    # The rule is still reported, and still scores nothing.
    assert [item["rule_id"] for item in evaluation.document["detections"]["items"]] == [
        "YARA_TRAC_PE_Packed_UPX"]
    # A declared-verdict rule keeps only TRAC's classification tags on the detection.
    # The rule's own tags are its author's vocabulary, and echoing "asyncrat" or
    # "win32" back would publish a classification TRAC did not make.
    static["yara_matches"] = [{"rule": "Some_Tool_Rule", "namespace": "repo",
                              "tags": ["malicious", "asyncrat", "win32"],
                              "meta": {"verdict": "malicious"}}]
    document = evaluate_evidence(data, static, {"status": "skipped", "_static_capabilities": {}},
                                 {}, {"clamav_result": "not_run"}).document

    assert document["detections"]["items"][0]["tags"] == ["yara", "malicious"]
    # A verdict-declaring rule still needs meta.family to name anything: "asyncrat"
    # here is one of the rule's own tags, and a tag is not an identification.
    assert document["verdict"]["family_guess"] == "unknown"
    assert "asyncrat" not in document["verdict"]["behavior_tags"]
    assert _semantics(document) == []
