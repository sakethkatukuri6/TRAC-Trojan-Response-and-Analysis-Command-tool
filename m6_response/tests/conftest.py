"""Pytest fixtures for M6 Response tests."""
import json
from pathlib import Path
import pytest

@pytest.fixture
def trojan_fixture():
    p = Path("contract/examples/valid_synthetic_trojan_record.json")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

@pytest.fixture
def benign_fixture():
    p = Path("contract/examples/valid_benign_test_binary.json")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)
