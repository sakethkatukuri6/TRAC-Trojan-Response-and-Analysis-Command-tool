"""Pipeline events endpoint."""
from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from m7_core.database import get_db
from m7_core.api.auth import get_current_module
from m7_core.services.event_processor import (
    EventProcessor,
    EventValidationError,
    EventProducerMismatchError,
    EventStateConflictError,
)

router = APIRouter(prefix="/api/v1", tags=["events"])


@router.post("/events", summary="Ingest pipeline event")
def post_event(
    event: Dict[str, Any],
    caller_module: str = Depends(get_current_module),
    db: Session = Depends(get_db),
):
    processor = EventProcessor(db)
    try:
        return processor.process_event(event, caller_module=caller_module)
    except EventValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"errors": e.errors})
    except EventProducerMismatchError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except EventStateConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
