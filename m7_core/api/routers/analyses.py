"""Analyses and Samples router enforcing declared bearerAuth security."""
from __future__ import annotations

import hashlib
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from sqlalchemy.orm import Session
from m7_core.database import get_db
from m7_core.api.auth import get_authenticated_identity
from m7_core.repository.analysis_repo import AnalysisRepository
from m7_core.services.analysis_service import AnalysisService

router = APIRouter(prefix="/api/v1", tags=["analyses"])


@router.post("/samples", summary="Upload a sample")
async def upload_sample(
    response: Response,
    file: UploadFile = File(...),
    archive_password: Optional[str] = Form(None),
    auth_identity: dict = Depends(get_authenticated_identity),
    db: Session = Depends(get_db),
):
    content = await file.read()
    if len(content) > 100 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds 100 MiB cap")

    sha256 = hashlib.sha256(content).hexdigest()
    repo = AnalysisRepository(db)
    analysis_id = str(uuid.uuid4())
    vault_id = str(uuid.uuid4())

    model, is_duplicate = repo.get_or_create(analysis_id=analysis_id, vault_id=vault_id, sha256=sha256)
    if is_duplicate:
        response.status_code = status.HTTP_200_OK
    else:
        response.status_code = status.HTTP_202_ACCEPTED

    return {
        "analysis_id": model.analysis_id,
        "vault_id": model.vault_id,
        "duplicate": is_duplicate
    }


@router.get("/analyses", summary="List analyses")
def list_analyses(
    status: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    auth_identity: dict = Depends(get_authenticated_identity),
    db: Session = Depends(get_db),
):
    service = AnalysisService(db)
    return service.list_analyses(status=status, verdict=verdict, limit=limit)


@router.get("/analyses/{analysis_id}", summary="Full analysis result")
def get_analysis(
    analysis_id: str,
    auth_identity: dict = Depends(get_authenticated_identity),
    db: Session = Depends(get_db),
):
    service = AnalysisService(db)
    doc = service.get_analysis_document(analysis_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")
    return doc
