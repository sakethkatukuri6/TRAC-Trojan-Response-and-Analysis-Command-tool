"""SQLAlchemy models for analyses, sections, and response actions."""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, Integer, ForeignKey
from m7_core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class AnalysisModel(Base):
    __tablename__ = "analyses"

    analysis_id = Column(String(36), primary_key=True)
    vault_id = Column(String(36), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    pipeline_status = Column(String(32), default="received", nullable=False)
    pipeline_stages = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class AnalysisSectionModel(Base):
    __tablename__ = "analysis_sections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(36), ForeignKey("analyses.analysis_id"), nullable=False, index=True)
    section_name = Column(String(64), nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    written_by = Column(String(32), nullable=False)
    written_at = Column(DateTime, default=utc_now, nullable=False)


class ActionModel(Base):
    __tablename__ = "actions"

    action_id = Column(String(36), primary_key=True)
    analysis_id = Column(String(36), ForeignKey("analyses.analysis_id"), nullable=False, index=True)
    type = Column(String(64), nullable=False)
    target = Column(String(1024), nullable=False)
    mode = Column(String(16), nullable=False)
    status = Column(String(32), nullable=False)
    playbook = Column(String(64), nullable=True)
    approval = Column(JSON, nullable=False)
    executed_at = Column(String(64), nullable=True)
    audit_ref = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
