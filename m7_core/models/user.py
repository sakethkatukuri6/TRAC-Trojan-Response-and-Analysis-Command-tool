"""SQLAlchemy model for user authentication."""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime
from m7_core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class UserModel(Base):
    __tablename__ = "users"

    username = Column(String(64), primary_key=True)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False)  # analyst, admin
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
