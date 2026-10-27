"""Test M6 CLI."""
import json
import subprocess
import sys
import uuid
from pathlib import Path


def test_m6_cli_execution(tmp_path):
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    out_file = tmp_path / "out_actions.json"

    res = subprocess.run(
        [
            sys.executable, "-m", "m6_response.cli",
            "--analysis-id", aid,
            "--vault-id", vid,
            "--out", str(out_file),
            "--input", "contract/examples/valid_synthetic_trojan_record.json"
        ],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "response_actions" in data
    assert isinstance(data["response_actions"], list)
    assert len(data["response_actions"]) > 0
