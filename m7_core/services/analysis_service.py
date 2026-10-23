"""Analysis service for managing analysis lifecycles."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from m7_core.repository.analysis_repo import AnalysisRepository


class AnalysisService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = AnalysisRepository(db)

    def get_analysis_document(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return self.repo.assemble_document(analysis_id)

    def get_analysis_model(self, analysis_id: str):
        return self.repo.get_by_id(analysis_id)

    def list_analyses(self, status: Optional[str] = None, verdict: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        analyses = self.repo.list_analyses(status=status, limit=limit)
        results = []
        for a in analyses:
            sections = self.repo.get_all_sections(a.analysis_id)
            v = sections.get("verdict", {})
            sc = sections.get("score", {})
            if verdict and v.get("label") != verdict:
                continue
            results.append({
                "analysis_id": a.analysis_id,
                "sha256": a.sha256,
                "status": a.pipeline_status,
                "verdict": v.get("label"),
                "severity": v.get("severity"),
                "score": sc.get("value")
            })
        return results
