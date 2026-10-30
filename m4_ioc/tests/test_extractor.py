from m4_ioc.extractor import extract_iocs


def test_static_candidates_do_not_become_fabricated_beacons():
    result = extract_iocs(
        b"",
        {"entropy": 0, "embedded_urls": ["hxxp://evil[.]example/path"], "strings": {"interesting": []}},
        {"status": "skipped", "_static_capabilities": {}},
        {"sha256": "a" * 64, "md5": "b" * 32},
    )

    assert result["beacons"] == []
    assert any(item["type"] == "url" for item in result["items"])
