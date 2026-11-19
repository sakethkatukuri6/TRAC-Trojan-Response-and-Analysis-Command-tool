"""Pytest fixtures for M2 Static Analysis."""
import pytest
from m7_core.tests.benign_pe import build_benign_pe


@pytest.fixture
def benign_pe_bytes():
    return build_benign_pe()
