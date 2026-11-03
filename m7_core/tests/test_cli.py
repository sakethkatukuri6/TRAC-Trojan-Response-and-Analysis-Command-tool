"""M7 CLI coverage: it emits only the pipeline section M7 actually holds."""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from m7_core.contract.loader import validate_section
from m7_core.database import init_db
from m7_core.services.analysis_service import AnalysisService
from m7_core.services.pipeline_runner import run_full_pipeline
from m7_core.tests.benign_pe import build_benign_pe


def _persist(tmp_path, monkeypatch) -> tuple[str, dict, str]:
    """Run the real pipeline into a throwaway database and return its ids."""
    db_url = f"sqlite:///{(tmp_path / 'm7_cli.db').as_posix()}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    init_db(engine)
    monkeypatch.setenv("VAULT_STORAGE_PATH", str(tmp_path / "vault"))
    monkeypatch.delenv("TRAC_CAPE_URL", raising=False)
    monkeypatch.delenv("TRAC_CAPE_TOKEN", raising=False)

    analysis_id = str(uuid.uuid4())
    document = run_full_pipeline(
        build_benign_pe(), original_filename="pe_fixture.exe", analysis_id=analysis_id
    )
    db = sessionmaker(bind=engine)()
    try:
        AnalysisService(db).persist_pipeline_result(document)
    finally:
        db.close()
    engine.dispose()
    return analysis_id, document, db_url


def _run_cli(analysis_id: str, out_file: Path, db_url: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "DATABASE_URL": db_url}
    return subprocess.run(
        [sys.executable, "-m", "m7_core.cli", "--analysis-id", analysis_id, "--out", str(out_file)],
        capture_output=True,
        text=True,
        env=env,
    )


def test_m7_cli_emits_the_persisted_pipeline_section(tmp_path, monkeypatch):
    analysis_id, document, db_url = _persist(tmp_path, monkeypatch)
    out_file = tmp_path / "out_pipeline.json"

    res = _run_cli(analysis_id, out_file, db_url)

    assert res.returncode == 0, res.stderr
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data) == 1  # writes ONLY {"pipeline": ...}
    assert data["pipeline"]["status"] == document["pipeline"]["status"]
    assert data["pipeline"]["stages"] == document["pipeline"]["stages"]
    assert validate_section("pipeline", data["pipeline"]) == []


def test_m7_cli_refuses_to_invent_a_pipeline_section_for_an_unknown_analysis(tmp_path, monkeypatch):
    _persist(tmp_path, monkeypatch)
    out_file = tmp_path / "out_pipeline.json"

    res = _run_cli(str(uuid.uuid4()), out_file, f"sqlite:///{(tmp_path / 'm7_cli.db').as_posix()}")

    assert res.returncode == 1
    assert "not recorded" in res.stderr
    assert not out_file.exists()
