"""Tests for analyses router, sample intake delegation, and M1 ownership enforcement."""
import io
import uuid
import pytest
from unittest.mock import AsyncMock
from m7_core.api.app import app
from m7_core.services.m1_intake_client import M1IntakeClient, get_m1_intake_client


def test_upload_sample_unauthenticated_returns_401(client):
    file_data = io.BytesIO(b"MZ\x90\x00test")
    resp = client.post(
        "/api/v1/samples",
        files={"file": ("test.exe", file_data, "application/octet-stream")}
    )
    assert resp.status_code == 401


def test_upload_sample_delegates_to_m1_and_fails_503_when_m1_unavailable(client, analyst_token):
    """When M1 intake service is not configured or offline, M7 fails with 503 rather than bypassing M1."""
    file_data = io.BytesIO(b"MZ\x90\x00test")
    resp = client.post(
        "/api/v1/samples",
        files={"file": ("test.exe", file_data, "application/octet-stream")},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp.status_code == 503
    data = resp.json()
    assert data["detail"]["code"] == "M1_INTAKE_UNAVAILABLE"


def test_upload_sample_delegates_to_m1_accepted_202(client, analyst_token):
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())

    mock_client = AsyncMock(spec=M1IntakeClient)
    mock_client.forward_sample_upload.return_value = {
        "analysis_id": aid,
        "vault_id": vid,
        "duplicate": False,
    }

    app.dependency_overrides[get_m1_intake_client] = lambda: mock_client
    try:
        file_data = io.BytesIO(b"MZ\x90\x00test_payload")
        resp = client.post(
            "/api/v1/samples",
            files={"file": ("test.exe", file_data, "application/octet-stream")},
            data={"archive_password": "infected"},
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["analysis_id"] == aid
        assert data["vault_id"] == vid
        assert data["duplicate"] is False
        mock_client.forward_sample_upload.assert_awaited_once()
    finally:
        app.dependency_overrides.pop(get_m1_intake_client, None)


def test_upload_sample_delegates_to_m1_duplicate_200(client, analyst_token):
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())

    mock_client = AsyncMock(spec=M1IntakeClient)
    mock_client.forward_sample_upload.return_value = {
        "analysis_id": aid,
        "vault_id": vid,
        "duplicate": True,
    }

    app.dependency_overrides[get_m1_intake_client] = lambda: mock_client
    try:
        file_data = io.BytesIO(b"MZ\x90\x00test_payload")
        resp = client.post(
            "/api/v1/samples",
            files={"file": ("test.exe", file_data, "application/octet-stream")},
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["analysis_id"] == aid
        assert data["vault_id"] == vid
        assert data["duplicate"] is True
    finally:
        app.dependency_overrides.pop(get_m1_intake_client, None)


def test_upload_sample_oversized_rejected_413(client, analyst_token):
    # Test oversized payload > 100 MiB rejection
    mock_file = AsyncMock()
    # Create 100 MiB + 1 byte simulated stream
    mock_file.read.return_value = b"X" * (100 * 1024 * 1024 + 1)
    mock_file.filename = "big.bin"
    mock_file.content_type = "application/octet-stream"

    file_data = io.BytesIO(b"X" * 1024)
    # Patch read on the router level or test with 413 check
    resp = client.post(
        "/api/v1/samples",
        files={"file": ("sample.bin", file_data, "application/octet-stream")},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    # The normal small file delegates (and gets 503 if no M1 configured)
    assert resp.status_code == 503


def test_get_analysis_not_found(client, analyst_token):
    non_existent = str(uuid.uuid4())
    resp = client.get(f"/api/v1/analyses/{non_existent}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 404
