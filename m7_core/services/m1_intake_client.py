"""M1 Intake client interface and HTTP implementation.

Enforces M1 intake ownership per contract:
- M1 Ingestion & Sample Vault owns sample intake and the 'sample' section.
- M7 exposes POST /api/v1/samples by streaming intake to M1.
"""
from __future__ import annotations

import io
import os
from typing import Any, Dict, Optional
import httpx
from fastapi import HTTPException, status
from m7_core.api.auth import create_module_token


class CappedStream(io.RawIOBase):
    """File-like streaming wrapper that enforces maximum byte cap without buffering in RAM."""
    def __init__(self, raw_file: Any, max_size: int = 100 * 1024 * 1024):
        self.raw = raw_file
        self.max_size = max_size
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        if isinstance(self.raw, bytes):
            chunk = self.raw[:size] if size != -1 else self.raw
            self.raw = self.raw[len(chunk):]
        elif hasattr(self.raw, "read"):
            chunk = self.raw.read(size)
        else:
            chunk = b""

        if chunk:
            self.bytes_read += len(chunk)
            if self.bytes_read > self.max_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="File exceeds 100 MiB cap"
                )
        return chunk


class M1IntakeClient:
    """Client for delegating sample intake to M1 Ingestion service."""

    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (base_url or os.getenv("M1_INTAKE_URL") or os.getenv("M1_URL") or "").rstrip("/")

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url)

    async def forward_sample_upload(
        self,
        file_obj: Any,
        filename: str,
        content_type: str = "application/octet-stream",
        archive_password: Optional[str] = None,
        max_size: int = 100 * 1024 * 1024,
    ) -> Dict[str, Any]:
        """Stream sample intake upload to M1 ingestion service enforcing size cap."""
        if not self.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "M1_INTAKE_UNAVAILABLE",
                    "message": "M1 intake service is not configured or unavailable. Sample intake is owned by M1 Ingestion.",
                },
            )

        token = create_module_token("M7")
        headers = {"Authorization": f"Bearer {token}"}
        data = {}
        if archive_password:
            data["archive_password"] = archive_password

        stream = CappedStream(file_obj, max_size=max_size)
        files = {"file": (filename, stream, content_type)}

        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=30.0) as client:
                resp = await client.post("/samples", files=files, data=data, headers=headers)
                if resp.status_code in (200, 202):
                    return resp.json()
                elif resp.status_code == 413:
                    raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds 100 MiB cap")
                elif resp.status_code == 422:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=resp.json())
                else:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail={"code": "M1_INTAKE_ERROR", "message": f"M1 intake returned error: {resp.status_code} {resp.text}"},
                    )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "M1_INTAKE_UNAVAILABLE", "message": f"Failed to connect to M1 intake service: {exc}"},
            )


def get_m1_intake_client() -> M1IntakeClient:
    return M1IntakeClient()
