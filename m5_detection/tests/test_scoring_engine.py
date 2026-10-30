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
    # 18 + 20 + 18 + 12 + 10 + 10 + 88 = 176 points of evidence against a 100-point scale.
    result = _score(entropy=7.9, capabilities=["injection", "c2_networking", "persistence",
                                                "evasion", "keylogging"], clamav="detected")
    components = result["score"]["components"]

    assert sum(c["contribution"] for c in components) == 100.0
    assert [c["contribution"] for c in components] == [10.2, 11.4, 10.2, 6.8, 5.7, 5.7, 50.0]
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
