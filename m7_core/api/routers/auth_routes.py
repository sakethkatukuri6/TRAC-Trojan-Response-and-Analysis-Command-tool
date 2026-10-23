"""Auth router for issuing test and user JWT tokens."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from m7_core.database import get_db
from m7_core.models.user import UserModel
from m7_core.api.auth import verify_password, create_user_token, create_module_token
from m7_core.api.schemas import LoginRequest, TokenResponse

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
def login_for_access_token(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    token = create_user_token(user.username, user.role)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/module-token/{module_name}", response_model=TokenResponse)
def get_module_token(module_name: str):
    if module_name not in ("M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid module name")
    token = create_module_token(module_name)
    return {"access_token": token, "token_type": "bearer"}
