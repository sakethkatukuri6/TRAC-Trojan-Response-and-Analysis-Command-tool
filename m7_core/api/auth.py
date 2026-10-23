"""Authentication and authorization utilities for M7 Core.

Provides:
- Cryptographic module service token validation (JWT)
- User JWT token issuance and verification (roles: analyst, admin)
- Argon2 password hashing
- Stable deployment secrets across processes and workers
- Unified bearer security verification for OpenAPI security compliance
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def get_stable_secret(env_var_name: str, fallback_file_key: str) -> str:
    """Retrieve secret from environment or load/persist in deployment secrets file."""
    env_val = os.getenv(env_var_name)
    if env_val:
        return env_val

    secrets_file = REPO_ROOT / ".secrets"
    data = {}
    if secrets_file.exists():
        try:
            with open(secrets_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}

    if fallback_file_key in data:
        return data[fallback_file_key]

    new_secret = secrets.token_hex(32)
    data[fallback_file_key] = new_secret
    try:
        with open(secrets_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass
    return new_secret


MODULE_SECRET = get_stable_secret("MODULE_SECRET", "module_jwt_secret")
USER_SECRET = get_stable_secret("USER_SECRET", "user_jwt_secret")
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security_bearer = HTTPBearer(auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_jwt_token(data: Dict[str, Any], secret: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(hours=8)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)


def create_module_token(module_name: str) -> str:
    if module_name not in ("M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"):
        raise ValueError(f"Invalid module name: {module_name}")
    return create_jwt_token({"sub": module_name, "type": "module"}, MODULE_SECRET)


def create_user_token(username: str, role: str) -> str:
    return create_jwt_token({"sub": username, "role": role, "type": "user"}, USER_SECRET)


def get_current_module(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> str:
    """Dependency returning authenticated module name. Only accepts signed module JWTs."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, MODULE_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "module":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a module service token")
        module = payload.get("sub")
        if not module or module not in ("M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid module identity in token")
        return module
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired module token"
        )


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> Dict[str, Any]:
    """Dependency returning authenticated user. Only accepts signed user JWTs."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, USER_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "user":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a user token")
        username = payload.get("sub")
        role = payload.get("role")
        if not username or not role:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user claims in token")
        return {"username": username, "role": role}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired user token"
        )


def get_authenticated_identity(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> Dict[str, Any]:
    """Unified bearer security dependency for endpoints accepting user or service authentication."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    token = credentials.credentials

    # Attempt user token decode
    try:
        payload = jwt.decode(token, USER_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") == "user":
            return {"type": "user", "identity": payload.get("sub"), "role": payload.get("role")}
    except JWTError:
        pass

    # Attempt module service token decode
    try:
        payload = jwt.decode(token, MODULE_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") == "module":
            return {"type": "module", "identity": payload.get("sub"), "role": "service"}
    except JWTError:
        pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired bearer token"
    )


def require_user_role(allowed_roles: List[str]):
    def role_checker(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role not permitted"
            )
        return user
    return role_checker
