"""M8 Report Generation Worker.

Consumes 'response.done' events, generates forensic PDF/HTML reports,
and emits contract-compliant 'report.done' events.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import uuid

from m8_ui_devops.reporting.pdf_report import generate_pdf_report
from m8_ui_devops.reporting.html_report import generate_html_report

logger = logging.getLogger("m8_report_worker")


def create_report_done_event(
    analysis_id: str,
    vault_id: str,
    report_vault_id: Optional[str] = None,
    attempt: int = 1,
) -> Dict[str, Any]:
    """Create a strictly contract-valid report.done event envelope."""
    return {
        "event_id": str(uuid.uuid4()),
        "type": "report.done",
        "analysis_id": analysis_id,
        "vault_id": vault_id,
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M8",
        "contract_version": "1.0.0",
        "attempt": attempt,
        "payload": {
            "report_vault_id": report_vault_id or vault_id,
        },
    }


def create_stage_failed_event(
    analysis_id: str,
    vault_id: str,
    code: str,
    message: str,
    retryable: bool = False,
    attempt: int = 1,
) -> Dict[str, Any]:
    """Create a contract-valid stage.failed event envelope."""
    return {
        "event_id": str(uuid.uuid4()),
        "type": "stage.failed",
        "analysis_id": analysis_id,
        "vault_id": vault_id,
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "producer": "M8",
        "contract_version": "1.0.0",
        "attempt": attempt,
        "payload": {
            "stage": "report",
            "code": code,
            "retryable": retryable,
            "message": message[:1000],
        },
    }


class ReportWorker:
    """Worker processing analysis documents to produce forensic reports and events."""

    def __init__(self, reports_dir: str | Path = "data/reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def process_analysis(
        self,
        doc: Dict[str, Any],
        out_pdf: Optional[str | Path] = None,
        out_html: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """Process an analysis document, write report files, and return report.done event."""
        analysis_id = doc.get("analysis_id", str(uuid.uuid4()))
        sample = doc.get("sample", {})
        vault_id = sample.get("vault_id", analysis_id)

        try:
            pdf_path = Path(out_pdf) if out_pdf else (self.reports_dir / f"{analysis_id}.pdf")
            html_path = Path(out_html) if out_html else (self.reports_dir / f"{analysis_id}.html")

            pdf_path.parent.mkdir(parents=True, exist_ok=True)
            html_path.parent.mkdir(parents=True, exist_ok=True)

            generate_pdf_report(doc, pdf_path)
            generate_html_report(doc, html_path)

            report_vault_id = str(uuid.uuid4())
            event = create_report_done_event(
                analysis_id=analysis_id,
                vault_id=vault_id,
                report_vault_id=report_vault_id,
            )
            return event
        except Exception as e:
            logger.exception("Failed to generate report for analysis %s", analysis_id)
            return create_stage_failed_event(
                analysis_id=analysis_id,
                vault_id=vault_id,
                code="REPORT_GENERATION_FAILED",
                message=str(e),
                retryable=True,
            )
