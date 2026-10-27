"""Authentication and authorization utilities for M7 Core.

Provides:
- Cryptographic module service token validation (JWT)
- User JWT token issuance and verification (roles: analyst, admin)
- Argon2 password hashing
- Stable deployment secrets across processes and workers (fail closed)
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
    """Retrieve secret from environment or load/persist in deployment secrets file.

    Fails closed:
    - If reading an existing deployment secrets file fails, raises RuntimeError.
    - If persisting a generated secret to disk fails, raises RuntimeError.
    - If running in production (TRAC_ENV=production or REQUIRE_DEPLOYMENT_SECRETS=1)
      and the secret is not explicitly provisioned, raises RuntimeError.
    """
    env_val = os.getenv(env_var_name)
    if env_val:
        return env_val

    is_production = (
        os.getenv("TRAC_ENV", "").lower() in ("prod", "production")
        or os.getenv("REQUIRE_DEPLOYMENT_SECRETS", "").lower() in ("1", "true")
    )
    if is_production:
        raise RuntimeError(
            f"Deployment secret '{env_var_name}' is unavailable. In production, deployment secrets must be configured."
        )

    secrets_file = REPO_ROOT / ".secrets"
    data = {}
    if secrets_file.exists():
        try:
            with open(secrets_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise RuntimeError(
                f"Deployment secrets file '{secrets_file}' exists but could not be read: {e}. Failing closed."
            ) from e

    if fallback_file_key in data and data[fallback_file_key]:
        return data[fallback_file_key]

    new_secret = secrets.token_hex(32)
    data[fallback_file_key] = new_secret
    try:
        with open(secrets_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        raise RuntimeError(
            f"Deployment secret '{env_var_name}' could not be persisted to '{secrets_file}'. Failing closed: {e}"
        ) from e

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
    payload = {
        "sub": module_name,
        "type": "module",
        "role": "service"
    }
    return create_jwt_token(payload, MODULE_SECRET, expires_delta=timedelta(days=7))


def create_user_token(username: str, role: str) -> str:
    payload = {
        "sub": username, "username": username,
        "role": role,
        "type": "user"
    }
    return create_jwt_token(payload, USER_SECRET, expires_delta=timedelta(hours=8))


def get_current_module(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> str:
    """Dependency returning authenticated module name. Only accepts signed module JWTs."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing module authorization token"
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, MODULE_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "module":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is not a valid module service token"
            )
        module_name = payload.get("sub")
        if not module_name:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
        return module_name
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
            detail="Missing user authorization token"
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, USER_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "user":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is not a valid user token"
            )
        return payload
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
                detail=f"Forbidden: role '{user.get('role')}' not authorized. Required: {allowed_roles}"
            )
        return user
    return role_checker
