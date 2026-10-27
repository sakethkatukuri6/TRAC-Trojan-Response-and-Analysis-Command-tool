"""Analyses and Samples router enforcing declared bearerAuth security and M1 intake ownership."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from sqlalchemy.orm import Session
from m7_core.database import get_db
from m7_core.api.auth import get_authenticated_identity
from m7_core.services.analysis_service import AnalysisService
from m7_core.services.m1_intake_client import M1IntakeClient, get_m1_intake_client

router = APIRouter(prefix="/api/v1", tags=["analyses"])


@router.post("/samples", summary="Upload a sample")
async def upload_sample(
    response: Response,
    file: UploadFile = File(...),
    archive_password: Optional[str] = Form(None),
    auth_identity: dict = Depends(get_authenticated_identity),
    intake_client: M1IntakeClient = Depends(get_m1_intake_client),
):
    """Upload a sample (M1 handles intake; M7 exposes it).

    Enforces M1 intake ownership and streams the proxy upload directly to M1
    while enforcing the 100 MiB cap before/during streaming without buffering
    the entire payload in memory.
    """
    if file.size and file.size > 100 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds 100 MiB cap"
        )

    result = await intake_client.forward_sample_upload(
        file_obj=file.file,
        filename=file.filename or "sample.bin",
        content_type=file.content_type or "application/octet-stream",
        archive_password=archive_password,
    )

    is_duplicate = result.get("duplicate", False)
    if is_duplicate:
        response.status_code = status.HTTP_200_OK
    else:
        response.status_code = status.HTTP_202_ACCEPTED

    return {
        "analysis_id": result["analysis_id"],
        "vault_id": result["vault_id"],
        "duplicate": is_duplicate,
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
