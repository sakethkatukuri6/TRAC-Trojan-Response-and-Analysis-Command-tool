"""Pydantic schemas for API serialization and request validation."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"


class ApiHealthResponse(BaseModel):
    status: str = "ok"
    db: str = "ok"


class AcceptedResponse(BaseModel):
    analysis_id: str
    vault_id: str
    duplicate: bool = False


class AnalysisSummaryResponse(BaseModel):
    analysis_id: str
    sha256: str
    status: str
    verdict: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
