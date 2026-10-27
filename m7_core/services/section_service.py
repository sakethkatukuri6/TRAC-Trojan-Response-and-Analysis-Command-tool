"""Section service enforcing ownership, schema validation, and state conflict rules."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from m7_core.contract.loader import get_owner_for_section, validate_section
from m7_core.repository.analysis_repo import AnalysisRepository
from m7_core.repository.action_repo import ActionRepository
from m7_core.repository.audit_repo import AuditRepository


class SectionOwnershipError(Exception):
    """Raised when a module attempts to write a section it does not own."""
    pass


class SectionValidationError(Exception):
    """Raised when section payload violates schema."""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


class SectionStateConflictError(Exception):
    """Raised when pipeline state does not permit the write."""
    pass


class AnalysisNotFoundError(Exception):
    """Raised when attempting to write a section to a non-existent analysis."""
    pass


class SectionService:
    def __init__(self, db: Session):
        self.db = db
        self.analysis_repo = AnalysisRepository(db)
        self.action_repo = ActionRepository(db)
        self.audit_repo = AuditRepository(db)

    def write_section(
        self,
        analysis_id: str,
        section_name: str,
        payload: Any,
        caller_module: str
    ) -> Dict[str, Any]:
        # 1. Pipeline section is owned exclusively by M7 orchestration and never through sections endpoint
        if section_name == "pipeline":
            raise SectionOwnershipError("SECTION_NOT_OWNED")

        # 2. Check ownership
        owner = get_owner_for_section(section_name)
        if owner is None or owner != caller_module:
            raise SectionOwnershipError("SECTION_NOT_OWNED")

        # 3. Check analysis exists (must be created by M1 intake) and is not in final state
        analysis = self.analysis_repo.get_by_id(analysis_id)
        if not analysis:
            raise AnalysisNotFoundError(
                f"Analysis '{analysis_id}' not found. Sections can only be written to an existing analysis created by M1 intake."
            )
        if analysis.pipeline_status in ("complete", "failed", "dead_letter"):
            raise SectionStateConflictError(f"Analysis in final state '{analysis.pipeline_status}' cannot be modified")

        # 4. Schema validation
        errs = validate_section(section_name, payload)
        if errs:
            raise SectionValidationError(errs)

        # 5. Persist section
        self.analysis_repo.save_section(
            analysis_id=analysis_id,
            section_name=section_name,
            payload=payload,
            written_by=caller_module
        )

        # 6. If response_actions, also populate ActionModel
        if section_name == "response_actions" and isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and "action_id" in item:
                    self.action_repo.save_action(analysis_id, item)

        # 7. Audit log
        self.audit_repo.log(
            actor=caller_module,
            action_type="write_section",
            detail={"section": section_name},
            analysis_id=analysis_id
        )

        return {"status": "stored", "section": section_name}
