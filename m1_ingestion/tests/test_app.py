import io
import json
import pytest
from fastapi import HTTPException, UploadFile
import m1_ingestion.app as app_mod
from m1_ingestion.app import download_sample, get_sample_metadata, health_check, upload_sample
from m1_ingestion.vault import SampleVault


@pytest.fixture(autouse=True)
def isolated_vault(tmp_path):
    orig_vault = app_mod.vault
    app_mod.vault = SampleVault(storage_dir=tmp_path)
    yield
    app_mod.vault = orig_vault


def test_health_endpoint():
    res = health_check()
    assert res == {"status": "ok", "service": "m1_ingestion"}


def test_upload_new_sample_accepted_202():
    file_bytes = b"MZ\x90\x00APIUploadTestPayload1"
    f = UploadFile(file=io.BytesIO(file_bytes), filename="malware_sample.exe")
    resp = upload_sample(file=f, submitter="analyst2")
    assert resp.status_code == 202
    data = json.loads(resp.body.decode("utf-8"))

    assert data["duplicate"] is False
    assert "analysis_id" in data
    assert "vault_id" in data
    assert data["sample"]["original_name"] == "malware_sample.exe"
    assert data["sample"]["file_type"] == "pe"
    assert data["sample"]["stored_defanged"] is True
    assert data["sample"]["stored_encrypted"] is True

    # Test downloading sample back
    dl_resp = download_sample(data["vault_id"])
    assert dl_resp.body == file_bytes


def test_upload_duplicate_sample_ok_200():
    file_bytes = b"MZ\x90\x00APIDuplicatePayload2"
    f1 = UploadFile(file=io.BytesIO(file_bytes), filename="sample_first.exe")
    r1 = upload_sample(file=f1)
    assert r1.status_code == 202
    vid1 = json.loads(r1.body.decode("utf-8"))["vault_id"]

    # Second upload with identical bytes
    f2 = UploadFile(file=io.BytesIO(file_bytes), filename="sample_second.exe")
    r2 = upload_sample(file=f2)
    assert r2.status_code == 200
    d2 = json.loads(r2.body.decode("utf-8"))
    assert d2["duplicate"] is True
    assert d2["vault_id"] == vid1
    assert d2["duplicate_of"] == vid1


def test_upload_empty_file_unprocessable_422():
    f = UploadFile(file=io.BytesIO(b""), filename="empty.exe")
    with pytest.raises(HTTPException) as exc_info:
        upload_sample(file=f)
    assert exc_info.value.status_code == 422


def test_download_not_found_404():
    with pytest.raises(HTTPException) as exc_info:
        download_sample("00000000-0000-0000-0000-000000000000")
    assert exc_info.value.status_code == 404
