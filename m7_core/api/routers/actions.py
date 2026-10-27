"""Actions router for approving and rejecting response actions."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from m7_core.database import get_db
from m7_core.api.auth import require_user_role
from m7_core.services.approval_service import (
    ApprovalService,
    ActionNotFoundError,
    ActionStateConflictError,
)

router = APIRouter(prefix="/api/v1", tags=["actions"])


@router.post("/analyses/{analysis_id}/actions/{action_id}/approve", summary="Approve a pending response action")
def approve_action(
    analysis_id: str,
    action_id: str,
    current_user: dict = Depends(require_user_role(["analyst", "admin"])),
    db: Session = Depends(get_db),
):
    service = ApprovalService(db)
    actor = current_user.get("username") or current_user.get("sub", "analyst")
    try:
        return service.approve_action(analysis_id, action_id, actor=actor)
    except ActionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ActionStateConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/analyses/{analysis_id}/actions/{action_id}/reject", summary="Reject a pending response action")
def reject_action(
    analysis_id: str,
    action_id: str,
    current_user: dict = Depends(require_user_role(["analyst", "admin"])),
    db: Session = Depends(get_db),
):
    service = ApprovalService(db)
    actor = current_user.get("username") or current_user.get("sub", "analyst")
    try:
        return service.reject_action(analysis_id, action_id, actor=actor)
    except ActionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ActionStateConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
