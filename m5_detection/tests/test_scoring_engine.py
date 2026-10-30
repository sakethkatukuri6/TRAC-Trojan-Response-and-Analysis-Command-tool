from m5_detection.scoring_engine import score_analysis


def test_score_has_no_hidden_baseline_or_fabricated_intel_hit():
    result = score_analysis(b"ordinary", {"entropy": 1.0, "packers": []}, {"status": "skipped", "_static_capabilities": {}}, {}, {"clamav_result": "not_run"})

    assert result["score"]["value"] == 0
    assert sum(item["contribution"] for item in result["score"]["components"]) == 0
    assert result["detections"]["intel_hits"] == []
