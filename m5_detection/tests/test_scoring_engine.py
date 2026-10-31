import json

from m5_detection.scoring_engine import (
    ENTROPY_ELEVATED_POINTS,
    FACTOR_MAX_POINTS,
    derive_confidence,
    score_analysis,
)


def _score(data=b"ordinary", *, entropy=1.0, capabilities=(), clamav="not_run",
            dynamic_status="skipped", yara=None):
    static = {"entropy": entropy, "packers": []}
    if yara is not None:
        static["yara_matches"] = yara
    dynamic = {"status": dynamic_status, "_static_capabilities": {c: {"matches": ["x"]} for c in capabilities}}
    return score_analysis(data, static, dynamic, {}, {"clamav_result": clamav})


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
    result = _score(entropy=7.9, capabilities=["injection", "c2_networking", "persistence",
                                                "evasion", "keylogging"], clamav="detected")
    components = result["score"]["components"]

    assert sum(c["contribution"] for c in components) == 100.0
    assert [c["contribution"] for c in components] == [10.2, 11.4, 10.2, 6.8, 5.7, 5.7, 50.0, 0.0]
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
        {"entropy": 6.2, "packers": ["anomalous_section:/4"]},
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
    assert [i["kind"] for i in result["detections"]["items"]] == ["behavior", "intel"]


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
