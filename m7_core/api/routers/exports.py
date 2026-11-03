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
        # Imported lazily so the API still boots without the optional STIX library.
        from m6_response.exports.stix_exporter import export_stix_bundle

        try:
            bundle = export_stix_bundle(
                doc.get("response_actions") or [],
                (doc.get("iocs") or {}).get("items") or [],
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"M6 STIX export failed: {type(exc).__name__}",
            )
        return Response(content=bundle, media_type="application/json")
    else:
        # M7 stores the document; only M8 renders reports. An empty %PDF header here
        # would be a file that no reader can open.
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="PDF reports are rendered by M8, not M7. Use GET "
                   "/api/reports/{analysis_id}/pdf on the M8 console.",
        )
