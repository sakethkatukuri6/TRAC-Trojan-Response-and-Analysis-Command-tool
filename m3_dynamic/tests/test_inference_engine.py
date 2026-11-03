from m3_dynamic.inference_engine import infer_behavior


def test_unconfigured_sandbox_is_skipped_and_never_fabricates_runtime_events(monkeypatch):
    monkeypatch.delenv("TRAC_CAPE_URL", raising=False)
    result = infer_behavior(
        b"MZ...CreateRemoteThread...VirtualAllocEx...",
        "pe",
        {"pe": {"imports": []}, "strings": {"interesting": []}},
        "sample.exe",
    )

    assert result["status"] == "skipped"
    assert "sandbox" not in result
    assert "process_tree" not in result
    assert result["_static_capabilities"]["injection"]["matches"] == ["createremotethread", "virtualallocex"]
