"""Analysis service for managing analysis lifecycles."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from m7_core.contract.loader import get_final_states, get_section_owners
from m7_core.repository.analysis_repo import AnalysisRepository
from m7_core.repository.audit_repo import AuditRepository
from m7_core.services.section_service import SectionService, SectionStateConflictError

# Terminal states derived from state_machine.yaml, shared with section_service.
FINAL_STATES = tuple(get_final_states())


class AnalysisService:
    #: Sections persisted on behalf of the module that owns each one, exactly as
    #: state_machine.yaml declares. A second list here would silently stop
    #: persisting a section the contract had just assigned to a module.
    #: `pipeline` is excluded: M7 mutates that status itself and section_service
    #: refuses it as a section.
    SECTION_WRITERS = {
        section: owner
        for section, owner in get_section_owners().items()
        if section != "pipeline"
    }

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
            # Both pointers identify bytes that must exist in the vault. Substituting
            # the analysis id for a vault id, or zeros for a digest, would index an
            # analysis under a sample that was never submitted.
            vault_id = sample.get("vault_id")
            sha256 = sample.get("sha256")
            if not vault_id or not sha256:
                raise ValueError(
                    f"Analysis '{analysis_id}' has no sample.vault_id/sha256; "
                    "a document must reference an ingested sample before it can be persisted."
                )
            self.repo.create(
                analysis_id=analysis_id,
                vault_id=vault_id,
                sha256=sha256,
                status="received",
            )
        elif existing.pipeline_status in FINAL_STATES:
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
            # A document that declares no state stays at intake; "complete" would be
            # a terminal claim M7 never observed.
            status=pipeline.get("status") or "received",
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


def load_stored_document(analysis_id: str) -> Dict[str, Any]:
    """Read a persisted analysis document out of the M7 database.

    Module CLIs publish the sections they own from this document, so an id that was
    never analysed raises instead of producing output for a sample nobody submitted.
    """
    from m7_core.database import SessionLocal

    db = SessionLocal()
    try:
        doc = AnalysisService(db).get_analysis_document(analysis_id)
    finally:
        db.close()
    if not doc:
        raise LookupError(f"Analysis '{analysis_id}' is not recorded in the M7 database.")
    return doc
