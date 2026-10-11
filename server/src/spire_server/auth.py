from __future__ import annotations

import hashlib
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .db import Agent, SessionLocal
from .settings import settings


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_enrollment_token(x_enrollment_token: str | None = Header(default=None)) -> None:
    if not x_enrollment_token or not secrets.compare_digest(x_enrollment_token.encode(), settings.enrollment_token.encode()):
        raise HTTPException(status_code=401, detail="invalid enrollment token")


def require_admin(authorization: str | None = Header(default=None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing admin token")
    token = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(token.encode(), settings.admin_token.encode()):
        raise HTTPException(status_code=401, detail="invalid admin token")


def require_agent(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Agent:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing agent token")
    token = authorization.removeprefix("Bearer ").strip()
    agent = db.query(Agent).filter(Agent.token_hash == hash_token(token)).one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="unknown agent")
    return agent
