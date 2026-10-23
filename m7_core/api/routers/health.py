"""Health routers."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from m7_core.database import get_db

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness")
def root_health():
    return {"status": "ok"}


@router.get("/api/v1/health", summary="API Liveness and DB health")
def api_health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"unhealthy: {e}"
    return {"status": "ok", "db": db_status}
