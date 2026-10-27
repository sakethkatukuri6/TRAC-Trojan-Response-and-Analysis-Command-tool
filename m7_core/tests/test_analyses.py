"""Tests for analyses router, sample intake delegation, streaming proxy, and M1 ownership enforcement."""
import io
import uuid
import pytest
from unittest.mock import AsyncMock, patch
import httpx
from fastapi import HTTPException
from m7_core.api.app import app
from m7_core.api.routers.analyses import upload_sample
from m7_core.services.m1_intake_client import M1IntakeClient, CappedStream, get_m1_intake_client


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


def test_capped_stream_enforces_cap_while_streaming():
    """Verify CappedStream streams bytes and aborts with 413 when exceeding cap."""
    small_buf = io.BytesIO(b"12345")
    s = CappedStream(small_buf, max_size=10)
    assert s.read(3) == b"123"
    assert s.read(3) == b"45"

    big_buf = io.BytesIO(b"123456789012345")
    s2 = CappedStream(big_buf, max_size=10)
    assert s2.read(5) == b"12345"
    with pytest.raises(HTTPException) as exc:
        s2.read(6)
    assert exc.value.status_code == 413
    assert "File exceeds 100 MiB cap" in exc.value.detail


@pytest.mark.asyncio
async def test_upload_sample_oversized_file_size_rejected_413():
    """Verify that if file.size exceeds 100 MiB, endpoint immediately rejects with 413 without reading."""
    mock_file = AsyncMock()
    mock_file.size = 100 * 1024 * 1024 + 1
    mock_file.file = io.BytesIO(b"oversized")
    mock_response = AsyncMock()

    with pytest.raises(HTTPException) as exc:
        await upload_sample(
            response=mock_response,
            file=mock_file,
            archive_password=None,
            auth_identity={"role": "analyst"},
            intake_client=AsyncMock(),
        )
    assert exc.value.status_code == 413
    assert "File exceeds 100 MiB cap" in exc.value.detail


@pytest.mark.asyncio
async def test_forward_sample_upload_streaming_cap_rejection():
    """Verify that M1IntakeClient streams the payload and aborts with 413 if the stream exceeds the cap."""
    client = M1IntakeClient(base_url="http://mock-m1:8000")
    large_stream = io.BytesIO(b"X" * 100)
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json={}))
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        with pytest.raises(HTTPException) as exc:
            await client.forward_sample_upload(
                file_obj=large_stream,
                filename="large.bin",
                max_size=50,
            )
        assert exc.value.status_code == 413
        assert "File exceeds 100 MiB cap" in exc.value.detail


def test_get_analysis_not_found(client, analyst_token):
    non_existent = str(uuid.uuid4())
    resp = client.get(f"/api/v1/analyses/{non_existent}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 404
