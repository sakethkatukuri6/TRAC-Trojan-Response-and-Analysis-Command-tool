"""Archive intake hardening: one payload, in memory only, under the size cap."""
from __future__ import annotations

import io
import tempfile
import zipfile
from typing import Optional

import pyzipper
import pytest

from m7_core.services import pipeline_runner
from m7_core.services.pipeline_runner import (
    ArchiveRejected,
    run_full_pipeline,
    unpack_if_archive,
)

PAYLOAD = b"this is a benign payload"


def _archive(entries: dict, *, aes: bool = False, password: Optional[str] = None) -> bytes:
    buffer = io.BytesIO()
    if aes:
        with pyzipper.AESZipFile(
            buffer, "w", compression=pyzipper.ZIP_STORED, encryption=pyzipper.WZ_AES
        ) as zf:
            if password:
                zf.setpassword(password.encode("utf-8"))
            for name, data in entries.items():
                zf.writestr(name, data)
    else:
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
    return buffer.getvalue()


def _code(archive: bytes, filename: str = "sample.zip", **kwargs) -> str:
    with pytest.raises(ArchiveRejected) as raised:
        unpack_if_archive(archive, filename, **kwargs)
    return raised.value.code


def test_password_protected_archive_yields_its_single_executable_payload():
    archive = _archive({"payload.exe": PAYLOAD}, aes=True, password="infected")

    data, name = unpack_if_archive(archive, "sample.zip", password="infected")

    assert (data, name) == (PAYLOAD, "payload.exe")


def test_unencrypted_archive_with_one_file_is_accepted():
    archive = _archive({"readme.txt": PAYLOAD})

    assert unpack_if_archive(archive, "sample.zip") == (PAYLOAD, "readme.txt")


def test_nested_member_is_reported_by_basename_only():
    archive = _archive({"drop/2024/tool.exe": PAYLOAD})

    assert unpack_if_archive(archive, "sample.zip") == (PAYLOAD, "tool.exe")


def test_empty_archive_is_rejected():
    buffer = io.BytesIO()
    zipfile.ZipFile(buffer, "w").close()

    assert _code(buffer.getvalue()) == "ARCHIVE_EMPTY"


def test_directory_only_archive_is_rejected():
    assert _code(_archive({"payloads/": b""})) == "ARCHIVE_EMPTY"


def test_zero_byte_payload_is_rejected():
    assert _code(_archive({"payload.exe": b""})) == "ARCHIVE_EMPTY"


def test_multiple_executable_candidates_are_ambiguous():
    archive = _archive({"dropper.exe": PAYLOAD, "helper.dll": PAYLOAD})

    with pytest.raises(ArchiveRejected) as raised:
        unpack_if_archive(archive, "sample.zip")

    assert raised.value.code == "ARCHIVE_AMBIGUOUS"
    assert "dropper.exe" in raised.value.message
    assert "helper.dll" in raised.value.message


def test_several_files_without_an_executable_are_unsupported():
    archive = _archive({"notes.txt": PAYLOAD, "script.ps1": PAYLOAD})

    assert _code(archive) == "ARCHIVE_UNSUPPORTED"


@pytest.mark.parametrize(
    "member",
    ["../evil.exe", "..\\evil.exe", "/etc/passwd.exe", "C:\\Windows\\evil.exe", "a/../../b.exe"],
)
def test_unsafe_member_names_are_rejected(member):
    archive = _archive({member: PAYLOAD})

    assert _code(archive) == "ARCHIVE_UNSAFE_NAME"


def test_corrupt_archive_is_rejected():
    assert _code(b"PK\x03\x04" + b"not really an archive") == "ARCHIVE_UNSUPPORTED"


def test_wrong_password_is_rejected_without_echoing_it():
    archive = _archive({"payload.exe": PAYLOAD}, aes=True, password="infected")

    with pytest.raises(ArchiveRejected) as raised:
        unpack_if_archive(archive, "sample.zip", password="hunter2-not-the-right-one")

    assert raised.value.code == "ARCHIVE_UNREADABLE"
    assert "hunter2" not in raised.value.message


def test_extracted_payload_over_the_cap_is_rejected(monkeypatch):
    monkeypatch.setattr(pipeline_runner, "MAX_FILE_SIZE", 16)
    archive = _archive({"payload.exe": b"x" * 4096})

    with pytest.raises(ArchiveRejected) as raised:
        unpack_if_archive(archive, "sample.zip")

    assert raised.value.code == "PAYLOAD_TOO_LARGE"
    assert "4096" in raised.value.message


def test_extraction_stays_in_memory_and_never_uses_temp_files(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("plaintext sample bytes must not be written to a temp file")

    monkeypatch.setattr(tempfile, "mkstemp", forbidden)
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", forbidden)
    monkeypatch.setattr(tempfile, "TemporaryFile", forbidden)
    monkeypatch.setattr(tempfile, "SpooledTemporaryFile", forbidden)

    archive = _archive({"payload.exe": PAYLOAD}, aes=True, password="infected")

    assert unpack_if_archive(archive, "sample.zip", password="infected") == (PAYLOAD, "payload.exe")


def test_rejected_archive_is_never_ingested(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_STORAGE_PATH", str(tmp_path / "vault"))
    archive = _archive({"one.exe": PAYLOAD, "two.exe": PAYLOAD})

    with pytest.raises(ArchiveRejected):
        run_full_pipeline(archive, original_filename="sample.zip")

    vault = tmp_path / "vault"
    assert not vault.exists() or list(vault.iterdir()) == []
