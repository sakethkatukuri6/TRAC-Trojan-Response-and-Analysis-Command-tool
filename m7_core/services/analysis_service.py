"""Analysis service for managing analysis lifecycles."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from m7_core.repository.analysis_repo import AnalysisRepository
from m7_core.repository.audit_repo import AuditRepository
from m7_core.services.section_service import SectionService, SectionStateConflictError


class AnalysisService:
    #: Sections persisted on behalf of the module that owns each one.
    SECTION_WRITERS = {
        "sample": "M1",
        "static": "M2",
        "dynamic": "M3",
        "iocs": "M4",
        "detections": "M5",
        "score": "M5",
        "verdict": "M5",
        "response_actions": "M6",
    }

    FINAL_STATES = ("complete", "failed", "dead_letter")

    def __init__(self, db: Session):
        self.db = db
        self.repo = AnalysisRepository(db)
        self.audit_repo = AuditRepository(db)
        self.section_service = SectionService(db)

    def get_analysis_document(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        doc = self.repo.assemble_document(analysis_id)
        if not doc:
            return None
        errors = self.list_stage_errors(analysis_id)
        if errors:
            doc.setdefault("pipeline", {})["errors"] = errors
        return doc

    def get_analysis_model(self, analysis_id: str):
        return self.repo.get_by_id(analysis_id)

    def list_analyses(self, status: Optional[str] = None, verdict: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        analyses = self.repo.list_analyses(status=status, limit=limit)
        results = []
        for a in analyses:
            sections = self.repo.get_all_sections(a.analysis_id)
            v = sections.get("verdict", {})
            sc = sections.get("score", {})
            sm = sections.get("sample", {})
            if verdict and v.get("label") != verdict:
                continue
            results.append({
                "analysis_id": a.analysis_id,
                "sha256": a.sha256,
                "original_name": sm.get("original_name"),
                "status": a.pipeline_status,
                "verdict": v.get("label"),
                "severity": v.get("severity"),
                "score": sc.get("value")
            })
        return results

    def persist_pipeline_result(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a finished pipeline document through M7's approved ownership flow.

        M7 remains the only writer to the database: every section is stored on
        behalf of the module that owns it, which keeps the ownership map and
        the schema validation of the sections endpoint authoritative.
        """
        analysis_id = doc["analysis_id"]
        sample = doc.get("sample") or {}

        existing = self.repo.get_by_id(analysis_id)
        if existing is None:
            self.repo.create(
                analysis_id=analysis_id,
                vault_id=sample.get("vault_id") or analysis_id,
                sha256=sample.get("sha256") or "0" * 64,
                status="received",
            )
        elif existing.pipeline_status in self.FINAL_STATES:
            raise SectionStateConflictError(
                f"Analysis '{analysis_id}' is already in final state '{existing.pipeline_status}'"
            )

        for section, writer in self.SECTION_WRITERS.items():
            if section not in doc:
                continue
            self.section_service.write_section(
                analysis_id=analysis_id,
                section_name=section,
                payload=doc[section],
                caller_module=writer,
            )

        for err in (doc.get("pipeline") or {}).get("errors") or []:
            self.audit_repo.log(
                actor=str(err.get("stage", "m7")).upper(),
                action_type="stage_failed",
                detail={
                    "stage": err.get("stage", "unknown"),
                    "code": err.get("code", "STAGE_FAILED"),
                    "message": str(err.get("message", ""))[:1000],
                },
                analysis_id=analysis_id,
            )

        pipeline = doc.get("pipeline") or {}
        self.repo.update_pipeline(
            analysis_id=analysis_id,
            status=pipeline.get("status", "complete"),
            stages=pipeline.get("stages"),
        )

        return self.get_analysis_document(analysis_id)

    def list_stage_errors(self, analysis_id: str) -> List[Dict[str, Any]]:
        """Return recorded stage failures, newest first, one entry per stage."""
        errors: List[Dict[str, Any]] = []
        seen = set()
        for entry in self.audit_repo.list_logs(analysis_id=analysis_id, limit=200):
            if entry.action_type != "stage_failed":
                continue
            detail = entry.detail or {}
            stage = str(detail.get("stage", "unknown"))
            if stage in seen:
                continue
            seen.add(stage)
            errors.append({
                "stage": stage,
                "code": str(detail.get("code", "STAGE_FAILED")),
                "message": str(detail.get("message", "")),
            })
        return errors
