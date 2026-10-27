"""Section writing router enforcing module ownership, analysis existence, and JSON schema."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from m7_core.database import get_db
from m7_core.api.auth import get_current_module
from m7_core.services.section_service import (
    SectionService,
    SectionOwnershipError,
    SectionValidationError,
    SectionStateConflictError,
    AnalysisNotFoundError,
)

router = APIRouter(prefix="/api/v1", tags=["sections"])


@router.put("/analyses/{analysis_id}/sections/{section}", summary="Module writes its own section")
async def write_section(
    analysis_id: str,
    section: str,
    request: Request,
    caller_module: str = Depends(get_current_module),
    db: Session = Depends(get_db),
):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Malformed JSON payload"
        )

    service = SectionService(db)
    try:
        result = service.write_section(
            analysis_id=analysis_id,
            section_name=section,
            payload=payload,
            caller_module=caller_module
        )
        return result
    except AnalysisNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": str(e)}
        )
    except SectionOwnershipError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "SECTION_NOT_OWNED", "message": str(e)}
        )
    except SectionValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "SCHEMA_VALIDATION_FAILED", "errors": e.errors}
        )
    except SectionStateConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "STATE_CONFLICT", "message": str(e)}
        )
