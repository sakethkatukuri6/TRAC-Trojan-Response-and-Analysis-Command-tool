"""Test M7 CLI."""
import json
import subprocess
import sys
import uuid
from pathlib import Path
from m7_core.contract.loader import validate_section


def test_m7_cli_execution(tmp_path):
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    out_file = tmp_path / "out_pipeline.json"

    res = subprocess.run(
        [sys.executable, "-m", "m7_core.cli", "--analysis-id", aid, "--vault-id", vid, "--out", str(out_file)],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "pipeline" in data
    assert len(data) == 1  # writes ONLY {"pipeline": ...}

    errs = validate_section("pipeline", data["pipeline"])
    assert errs == []
