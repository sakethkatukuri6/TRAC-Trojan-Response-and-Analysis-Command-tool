"""Exports router for report and IOC export enforcing declared bearerAuth security."""
from __future__ import annotations

import json
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from m7_core.database import get_db
from m7_core.api.auth import get_authenticated_identity
from m7_core.services.analysis_service import AnalysisService

router = APIRouter(prefix="/api/v1", tags=["exports"])


@router.get("/analyses/{analysis_id}/export", summary="Export IOCs/report")
def export_analysis(
    analysis_id: str,
    format: str = Query(..., pattern="^(json|stix|csv|pdf)$"),
    auth_identity: dict = Depends(get_authenticated_identity),
    db: Session = Depends(get_db),
):
    service = AnalysisService(db)
    doc = service.get_analysis_document(analysis_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    if format == "json":
        return Response(content=json.dumps(doc, indent=2), media_type="application/json")
    elif format == "csv":
        actions = doc.get("response_actions", [])
        csv_lines = ["action_id,type,target,mode,status"]
        for a in actions:
            csv_lines.append(f"{a.get('action_id')},{a.get('type')},{a.get('target')},{a.get('mode')},{a.get('status')}")
        return Response(content="\n".join(csv_lines), media_type="text/csv")
    elif format == "stix":
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{analysis_id}",
            "objects": []
        }
        return Response(content=json.dumps(stix_bundle, indent=2), media_type="application/json")
    else:
        return Response(content=f"%PDF-1.4 synthetic report for {analysis_id}", media_type="application/pdf")
