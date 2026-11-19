"""Operator authentication for the M8 console.

Sessions are HttpOnly cookies carrying an M7-signed user JWT. The console
never mints user tokens itself beyond the login exchange; verification uses
M7's USER_SECRET so a session is exactly as trustworthy as the M7 API's own
user tokens. The previous UI exposed a client-side role dropdown that had no
enforcement whatsoever — server-side role checks replace it.
"""
from __future__ import annotations

import logging
import os
import secrets

from fastapi import HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from m7_core.api.auth import (
    ALGORITHM,
    USER_SECRET,
    get_password_hash,
    verify_password,
)
from m7_core.models.user import UserModel

logger = logging.getLogger(__name__)

COOKIE_NAME = "trac_console_session"
COOKIE_MAX_AGE_SECONDS = 8 * 3600  # matches the M7 user-token lifetime
CONSOLE_ROLES = ("analyst", "admin")


def ensure_bootstrap_admin(db: Session) -> None:
    """Create the initial admin account when the users table is empty.

    The password comes from TRAC_BOOTSTRAP_ADMIN_PASSWORD. When unset, a
    random one-time password is generated and printed once to the operator
    console; it is never stored in plaintext anywhere.
    """
    if db.query(UserModel).first() is not None:
        return

    password = os.getenv("TRAC_BOOTSTRAP_ADMIN_PASSWORD", "")
    if password:
        logger.info("Bootstrap admin account created from TRAC_BOOTSTRAP_ADMIN_PASSWORD.")
    else:
        password = secrets.token_urlsafe(16)
        print(
            "\n[TRAC] No users exist and TRAC_BOOTSTRAP_ADMIN_PASSWORD is not set.\n"
            f"[TRAC] One-time admin password: {password}\n"
            "[TRAC] Store it now — it is not shown again. Log in as 'admin' and change it.\n",
            flush=True,
        )
    db.add(UserModel(username="admin", hashed_password=get_password_hash(password), role="admin"))
    db.commit()


def decode_session_token(token: str) -> dict:
    payload = jwt.decode(token, USER_SECRET, algorithms=[ALGORITHM])
    if payload.get("type") != "user":
        raise JWTError("not a user token")
    return payload


def authenticate_user(db: Session, username: str, password: str) -> dict | None:
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if not user or not user.is_active or not verify_password(password, user.hashed_password):
        return None
    return {"username": user.username, "role": user.role}


def get_console_user(request: Request) -> dict | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        return decode_session_token(token)
    except JWTError:
        return None


def require_console_user(allowed_roles=CONSOLE_ROLES):
    def dependency(request: Request) -> dict:
        user = get_console_user(request)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Console authentication required. Log in first.",
            )
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.get('role')}' is not authorized for this action.",
            )
        return user

    return dependency
