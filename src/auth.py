"""Authentication and authorization helpers for the activities API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


TOKEN_TTL_SECONDS = 60 * 60
PASSWORD_ITERATIONS = 600_000
bearer_scheme = HTTPBearer(auto_error=False)
active_tokens: dict[str, "AuthUser"] = {}
token_expirations: dict[str, float] = {}


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str
    tenant_id: str


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Create a portable PBKDF2 password record for AUTH_USERS_JSON."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_ITERATIONS
    )
    return "pbkdf2_sha256${}${}".format(
        base64.urlsafe_b64encode(salt).decode(),
        base64.urlsafe_b64encode(digest).decode(),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, encoded_salt, encoded_digest = stored_hash.split("$", 2)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(encoded_salt.encode())
        expected = base64.urlsafe_b64decode(encoded_digest.encode())
    except (ValueError, TypeError):
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


def _configured_users() -> dict[str, dict[str, str]]:
    raw_users = os.getenv("AUTH_USERS_JSON", "{}")
    try:
        users = json.loads(raw_users)
    except json.JSONDecodeError as error:
        raise RuntimeError("AUTH_USERS_JSON must contain valid JSON") from error
    if not isinstance(users, dict):
        raise RuntimeError("AUTH_USERS_JSON must be a JSON object")
    return users


def authenticate(username: str, password: str) -> AuthUser | None:
    record = _configured_users().get(username)
    if not isinstance(record, dict):
        return None
    password_hash = record.get("password_hash", "")
    if not isinstance(password_hash, str) or not verify_password(password, password_hash):
        return None
    role = record.get("role", "staff")
    tenant_id = record.get("tenant_id", "mergington-high-school")
    if role not in {"admin", "staff"} or not isinstance(tenant_id, str):
        return None
    return AuthUser(username=username, role=role, tenant_id=tenant_id)


def issue_token(user: AuthUser) -> tuple[str, int]:
    token = secrets.token_urlsafe(32)
    active_tokens[token] = user
    token_expirations[token] = time.time() + TOKEN_TTL_SECONDS
    return token, TOKEN_TTL_SECONDS


def revoke_token(token: str) -> None:
    active_tokens.pop(token, None)
    token_expirations.pop(token, None)


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    user = active_tokens.get(token)
    if user is None or token_expirations.get(token, 0) <= time.time():
        revoke_token(token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(*roles: str):
    def dependency(user: AuthUser = Depends(current_user)) -> AuthUser:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return dependency


def require_tenant(user: AuthUser, tenant_id: str) -> None:
    if not hmac.compare_digest(user.tenant_id, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant access denied",
        )