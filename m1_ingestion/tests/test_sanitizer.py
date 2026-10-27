import re
import pytest
from m1_ingestion.sanitizer import ALLOWED_PATTERN, sanitize_filename


def test_sanitize_clean_filename():
    assert sanitize_filename("invoice.exe") == "invoice.exe"
    assert sanitize_filename("report 2026-10.pdf") == "report 2026-10.pdf"


def test_sanitize_directory_traversal():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\Windows\\System32\\calc.exe") == "calc.exe"
    assert sanitize_filename("/var/tmp/sample.bin") == "sample.bin"


def test_sanitize_special_characters():
    result = sanitize_filename("malware!#$@%^&*().exe")
    assert ALLOWED_PATTERN.match(result)
    assert not any(c in result for c in "!#$@%^&*")


def test_sanitize_max_length_preserves_ext():
    long_name = "a" * 300 + ".exe"
    sanitized = sanitize_filename(long_name)
    assert len(sanitized) <= 255
    assert sanitized.endswith(".exe")
    assert ALLOWED_PATTERN.match(sanitized)


def test_sanitize_empty_fallback():
    assert sanitize_filename("") == "sample.bin"
    assert sanitize_filename("   ") == "sample.bin"
    assert sanitize_filename("../..") == "sample.bin"

