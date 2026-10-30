"""M8 UI, Reporting & DevOps CLI.

Usage:
  python -m m8_ui_devops.cli --analysis-id <uuid> --vault-id <uuid> --out <path>
  python -m m8_ui_devops.cli --serve-ui --port 8088
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import uuid
import webbrowser

from m8_ui_devops.evidence import build_presentation
from m8_ui_devops.reporting.models import ReportData
from m8_ui_devops.reporting.pdf_report import generate_pdf_report
from m8_ui_devops.reporting.html_report import generate_html_report
from m8_ui_devops.reporting.worker import create_report_done_event, ReportWorker


def find_available_port(host: str, preferred_port: int) -> int:
    """Find a port that can be bound, falling back if preferred_port is forbidden or busy."""
    import socket
    candidates = [preferred_port, 8088, 8081, 8090, 8501, 3000, 5000]
    for p in candidates:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((host, p))
                return p
        except OSError:
            continue
    for p in range(8081, 8200):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((host, p))
                return p
        except OSError:
            continue
    return preferred_port


def create_dashboard_app(host: str = "127.0.0.1", port: int = 8088):
    """Build the M8 command console FastAPI application.

    The console is a presentation layer over M7: samples are analysed by the
    pipeline and the finished document is persisted by M7, which owns
    pipeline and database state. M8 never writes analysis state itself.
    """
    from fastapi import Depends, FastAPI, File, Form, HTTPException, Response, UploadFile
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from sqlalchemy.orm import Session

    from m7_core.database import get_db
    from m7_core.services.analysis_service import AnalysisService
    from m7_core.services.pipeline_runner import ArchiveRejected, run_full_pipeline
    from m7_core.services.section_service import SectionStateConflictError

    app = FastAPI(title="TRAC Security Command Platform (M8)", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def load_document(analysis_id: str, db: Session):
        doc = AnalysisService(db).get_analysis_document(analysis_id)
        if not doc:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return doc

    @app.get("/api/health")
    def health_check():
        return {"status": "ok", "module": "M8_UI_DEVOPS", "version": "1.0.0"}

    @app.get("/api/analyses", summary="List analyses persisted by M7")
    def list_analyses(db: Session = Depends(get_db)):
        return AnalysisService(db).list_analyses(limit=100)

    @app.get("/api/analyses/{analysis_id}/view", summary="Contract document with evidence labels")
    def get_analysis_view(analysis_id: str, db: Session = Depends(get_db)):
        doc = load_document(analysis_id, db)
        return {"document": doc, "presentation": build_presentation(doc)}

    @app.post("/api/samples/upload", summary="Analyse an uploaded sample")
    async def upload_sample_endpoint(
        file: UploadFile = File(...),
        archive_password: str = Form("infected"),
        db: Session = Depends(get_db),
    ):
        content = await file.read()
        if len(content) > 100 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File exceeds 100 MiB limit")
        if not content:
            raise HTTPException(status_code=422, detail="Uploaded file is empty")

        try:
            document = run_full_pipeline(
                raw_bytes=content,
                original_filename=file.filename or "sample.exe",
                archive_password=archive_password,
            )
        except ArchiveRejected as exc:
            status_code = 413 if exc.code == "PAYLOAD_TOO_LARGE" else 400
            raise HTTPException(status_code=status_code, detail=f"{exc.code}: {exc.message}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Pipeline execution failed: {exc}")

        try:
            AnalysisService(db).persist_pipeline_result(document)
        except SectionStateConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"M7 could not persist the analysis: {exc}")

        return {"document": document, "presentation": build_presentation(document)}

    @app.get("/api/reports/{analysis_id}/pdf")
    def get_report_pdf(analysis_id: str, db: Session = Depends(get_db)):
        doc = load_document(analysis_id, db)
        out_path = Path(f"data/reports/{analysis_id}.pdf")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        generate_pdf_report(doc, out_path)
        return Response(content=out_path.read_bytes(), media_type="application/pdf")

    @app.get("/api/reports/{analysis_id}/html")
    def get_report_html(analysis_id: str, db: Session = Depends(get_db)):
        doc = load_document(analysis_id, db)
        html = generate_html_report(doc)
        return Response(content=html, media_type="text/html")

    # The console is version controlled at ui/standalone.html. A React build in
    # ui/dist is only used when the standalone console is unavailable.
    standalone_html = Path(__file__).resolve().parent / "ui" / "standalone.html"
    dist_index = Path(__file__).resolve().parent / "ui" / "dist" / "index.html"

    if standalone_html.exists():
        @app.get("/")
        def serve_index():
            return Response(content=standalone_html.read_text(encoding="utf-8"), media_type="text/html")
    elif dist_index.exists():
        app.mount("/", StaticFiles(directory=str(dist_index.parent), html=True), name="ui")
    else:
        @app.get("/")
        def serve_fallback():
            return {"message": "TRAC M8 UI server running."}

    return app


def serve_dashboard(host: str = "127.0.0.1", port: int = 8088, open_browser: bool = False):
    """Serve the web UI using FastAPI / uvicorn."""
    import uvicorn
    from m7_core.database import init_db

    init_db()

    actual_port = find_available_port(host, port)
    if actual_port != port:
        print(f"[!] Notice: Port {port} is unavailable or restricted by Windows access permissions.")
        print(f"[*] Automatically falling back to available port {actual_port}.")
        port = actual_port

    app = create_dashboard_app(host=host, port=port)

    print(f"\n[+] TRAC Threat Response Command Center running on http://{host}:{port}")
    if open_browser:
        webbrowser.open(f"http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")


def main():
    parser = argparse.ArgumentParser(description="M8 UI, Reporting & DevOps CLI")
    parser.add_argument("--analysis-id", required=False, default=None, help="Analysis UUID")
    parser.add_argument("--vault-id", required=False, default=None, help="Vault UUID")
    parser.add_argument("--out", required=False, default=None, help="Output path (PDF, HTML, or report info)")
    parser.add_argument("--out-pdf", required=False, default=None, help="Output PDF path")
    parser.add_argument("--out-html", required=False, default=None, help="Output HTML path")
    parser.add_argument("--event", required=False, default=None, help="Output event path")
    parser.add_argument("--input", required=False, default=None, help="Input analysis JSON document")
    parser.add_argument("--serve-ui", action="store_true", help="Launch the local SOC analyst web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind for UI server")
    parser.add_argument("--port", type=int, default=8088, help="Port to bind for UI server")
    parser.add_argument("--open-browser", action="store_true", help="Open browser on server launch")

    args = parser.parse_args()

    if args.serve_ui:
        serve_dashboard(host=args.host, port=args.port, open_browser=args.open_browser)
        return

    # CLI Report Generation Mode
    analysis_id = args.analysis_id or str(uuid.uuid4())
    vault_id = args.vault_id or analysis_id

    # Load input analysis fixture
    if args.input and Path(args.input).exists():
        with open(args.input, "r", encoding="utf-8") as f:
            doc = json.load(f)
    else:
        example_path = Path("contract/examples/valid_synthetic_trojan_record.json")
        if example_path.exists():
            with open(example_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        else:
            doc = {
                "contract_version": "1.0.0",
                "analysis_id": analysis_id,
                "sample": {
                    "vault_id": vault_id,
                    "sha256": "c" * 64,
                    "md5": "d" * 32,
                    "size_bytes": 1024,
                    "file_type": "pe",
                    "original_name": "sample.exe",
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "stored_defanged": True,
                    "stored_encrypted": True,
                },
                "pipeline": {"status": "complete", "stages": {}},
            }

    doc["analysis_id"] = analysis_id
    if "sample" in doc:
        doc["sample"]["vault_id"] = vault_id

    # Determine output destinations
    out_pdf = args.out_pdf
    out_html = args.out_html
    if args.out:
        if args.out.endswith(".pdf"):
            out_pdf = args.out
        elif args.out.endswith(".html"):
            out_html = args.out

    worker = ReportWorker()
    event = worker.process_analysis(doc, out_pdf=out_pdf, out_html=out_html)

    # Save event
    event_path = Path(args.event) if args.event else Path("m8_ui_devops/contract_events/report_done.json")
    event_path.parent.mkdir(parents=True, exist_ok=True)
    with open(event_path, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=2)

    print(f"[+] M8 report processing complete.")
    if out_pdf:
        print(f"    PDF Report:  {out_pdf}")
    if out_html:
        print(f"    HTML Report: {out_html}")
    print(f"    Event:       {event_path}")
    if event.get("type") == "report.done":
        print(f"    Report Vault ID: {event['payload']['report_vault_id']}")
    else:
        print(f"    Status:      {event.get('type')} ({event.get('payload', {}).get('code')})")


if __name__ == "__main__":
    main()
