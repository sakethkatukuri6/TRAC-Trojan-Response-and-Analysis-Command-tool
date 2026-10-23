"""Analysis and Section repository."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from m7_core.models.analysis import AnalysisModel, AnalysisSectionModel


class AnalysisRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, analysis_id: str) -> Optional[AnalysisModel]:
        return self.db.query(AnalysisModel).filter(AnalysisModel.analysis_id == analysis_id).first()

    def get_by_sha256(self, sha256: str) -> Optional[AnalysisModel]:
        return self.db.query(AnalysisModel).filter(AnalysisModel.sha256 == sha256).first()

    def create(self, analysis_id: str, vault_id: str, sha256: str, status: str = "received", stages: Optional[Dict[str, str]] = None) -> AnalysisModel:
        initial_stages = stages or {
            "ingest": "done",
            "static": "pending",
            "dynamic": "pending",
            "iocs": "pending",
            "scoring": "pending",
            "response": "pending",
            "report": "pending"
        }
        item = AnalysisModel(
            analysis_id=analysis_id,
            vault_id=vault_id,
            sha256=sha256,
            pipeline_status=status,
            pipeline_stages=initial_stages
        )
        self.db.add(item)
        self.db.commit()
        self.db.refresh(item)
        return item

    def get_or_create(self, analysis_id: str, vault_id: str, sha256: str) -> tuple[AnalysisModel, bool]:
        existing = self.get_by_id(analysis_id)
        if existing:
            return existing, False
        existing_sha = self.get_by_sha256(sha256)
        if existing_sha:
            return existing_sha, True
        return self.create(analysis_id, vault_id, sha256), False

    def list_analyses(self, status: Optional[str] = None, limit: int = 50) -> List[AnalysisModel]:
        q = self.db.query(AnalysisModel)
        if status:
            q = q.filter(AnalysisModel.pipeline_status == status)
        return q.limit(limit).all()

    def update_pipeline(self, analysis_id: str, status: Optional[str] = None, stages: Optional[Dict[str, str]] = None) -> Optional[AnalysisModel]:
        item = self.get_by_id(analysis_id)
        if not item:
            return None
        if status:
            item.pipeline_status = status
        if stages:
            current = dict(item.pipeline_stages or {})
            current.update(stages)
            item.pipeline_stages = current
        self.db.commit()
        self.db.refresh(item)
        return item

    def save_section(self, analysis_id: str, section_name: str, payload: Any, written_by: str) -> AnalysisSectionModel:
        # Check if section exists for analysis
        sec = self.db.query(AnalysisSectionModel).filter(
            AnalysisSectionModel.analysis_id == analysis_id,
            AnalysisSectionModel.section_name == section_name
        ).first()
        if sec:
            sec.payload = payload
            sec.written_by = written_by
        else:
            sec = AnalysisSectionModel(
                analysis_id=analysis_id,
                section_name=section_name,
                payload=payload,
                written_by=written_by
            )
            self.db.add(sec)
        self.db.commit()
        self.db.refresh(sec)
        return sec

    def get_section(self, analysis_id: str, section_name: str) -> Optional[AnalysisSectionModel]:
        return self.db.query(AnalysisSectionModel).filter(
            AnalysisSectionModel.analysis_id == analysis_id,
            AnalysisSectionModel.section_name == section_name
        ).first()

    def get_all_sections(self, analysis_id: str) -> Dict[str, Any]:
        secs = self.db.query(AnalysisSectionModel).filter(AnalysisSectionModel.analysis_id == analysis_id).all()
        return {s.section_name: s.payload for s in secs}

    def assemble_document(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        analysis = self.get_by_id(analysis_id)
        if not analysis:
            return None
        doc: Dict[str, Any] = {
            "contract_version": "1.0.0",
            "analysis_id": analysis.analysis_id,
            "pipeline": {
                "status": analysis.pipeline_status,
                "stages": analysis.pipeline_stages
            }
        }
        sections = self.get_all_sections(analysis_id)
        doc.update(sections)
        return doc
