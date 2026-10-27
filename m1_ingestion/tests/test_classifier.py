import pytest
from m1_ingestion.classifier import classify_file

ALLOWED_TYPES = {"pe", "elf", "macho", "office", "pdf", "script", "archive", "other"}


def test_classify_pe():
    t, mime = classify_file(b"MZ\x90\x00\x03\x00\x00\x00", "test.exe")
    assert t == "pe"
    assert t in ALLOWED_TYPES


def test_classify_elf():
    t, mime = classify_file(b"\x7fELF\x02\x01\x01\x00", "payload.bin")
    assert t == "elf"
    assert t in ALLOWED_TYPES


def test_classify_pdf():
    t, mime = classify_file(b"%PDF-1.7\r\n...", "sample.pdf")
    assert t == "pdf"
    assert t in ALLOWED_TYPES


def test_classify_office_ole():
    t, mime = classify_file(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1test", "doc.doc")
    assert t == "office"
    assert t in ALLOWED_TYPES


def test_classify_archive_zip():
    t, mime = classify_file(b"PK\x03\x04\x14\x00\x00\x00", "archive.zip")
    assert t == "archive"
    assert t in ALLOWED_TYPES


def test_classify_archive_7z():
    t, mime = classify_file(b"7z\xbc\xaf\x27\x1c\x00\x04", "backup.7z")
    assert t == "archive"
    assert t in ALLOWED_TYPES


def test_classify_script():
    t, mime = classify_file(b"#!/bin/bash\necho hello\n", "script.sh")
    assert t == "script"
    assert t in ALLOWED_TYPES

    t2, mime2 = classify_file(b"Write-Host 'test'", "script.ps1")
    assert t2 == "script"
    assert t2 in ALLOWED_TYPES


def test_classify_other():
    t, mime = classify_file(b"random raw text data", "plain.txt")
    assert t == "other"
    assert t in ALLOWED_TYPES

