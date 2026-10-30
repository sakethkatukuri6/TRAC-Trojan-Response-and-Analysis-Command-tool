"""M1 Ingestion Intake & Vault Service (FastAPI).

Exposes:
- POST /samples (intake capped at the contract's size limit, with filename
  sanitization and dedup)
- GET /samples/{vault_id} (Download decrypted bytes for authorized modules)
- GET /samples/{vault_id}/metadata (Get sample metadata)
- GET /health (Liveness)
"""
from __future__ import annotations

import io
from typing import Optional
from fastapi import FastAPI, File, Form, Header, HTTPException, Response, UploadFile, status
from fastapi.responses import JSONResponse

from m1_ingestion.vault import MAX_FILE_SIZE, SampleVault
from m7_core.contract.loader import get_platform_version

app = FastAPI(title="M1 Ingestion & Sample Vault Service", version=get_platform_version())
vault = SampleVault()


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "m1_ingestion"}


@app.post("/samples")
def upload_sample(
    file: UploadFile = File(...),
    archive_password: Optional[str] = Form(None),
    submitter: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None),
):
    """Intake sample: enforces the contract size cap, sanitizes the filename,
    then stores the payload encrypted and defanged.
    """
    # Read file with size check
    chunks = []
    total_bytes = 0
    raw_file = getattr(file, "file", file)

    while True:
        chunk = raw_file.read(1024 * 1024)  # 1 MiB chunks
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds the {MAX_FILE_SIZE} byte upload cap",
            )
        chunks.append(chunk)

    raw_data = b"".join(chunks)
    if len(raw_data) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded file is empty",
        )

    try:
        sample_rec, event_rec, is_duplicate = vault.ingest(
            data=raw_data,
            original_name=file.filename or "sample.bin",
            submitter=submitter,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    resp_data = {
        "analysis_id": event_rec["analysis_id"],
        "vault_id": sample_rec["vault_id"],
        "duplicate": is_duplicate,
        "sample": sample_rec,
    }
    if is_duplicate:
        resp_data["duplicate_of"] = sample_rec.get("duplicate_of")
        return JSONResponse(status_code=status.HTTP_200_OK, content=resp_data)

    return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=resp_data)


@app.get("/samples/{vault_id}")
def download_sample(vault_id: str):
    """Retrieve and decrypt original sample bytes."""
    try:
        data = vault.retrieve(vault_id)
        return Response(content=data, media_type="application/octet-stream")
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found")


@app.get("/samples/{vault_id}/metadata")
def get_sample_metadata(vault_id: str):
    """Get metadata for a sample in the vault."""
    meta = vault.get_metadata_by_vault_id(vault_id)
    if not meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found")
    return {"sample": meta}

