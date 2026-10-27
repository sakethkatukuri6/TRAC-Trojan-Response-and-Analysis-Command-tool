import json
import subprocess
import sys
import uuid
import pytest
from pathlib import Path
import contract.tools.check_module as cm


def test_cli_execution_with_file(tmp_path):
    test_sample = tmp_path / "test_sample.exe"
    test_sample.write_bytes(b"MZ\x90\x00CLITestPayload12345")

    out_file = tmp_path / "contract_out" / "sample.json"
    ev_file = tmp_path / "contract_events" / "sample_received.json"

    cmd = [
        sys.executable,
        "-m",
        "m1_ingestion.cli",
        "--file",
        str(test_sample),
        "--out",
        str(out_file),
        "--event-out",
        str(ev_file),
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"CLI failed: {res.stderr}"
    assert out_file.exists()
    assert ev_file.exists()

    doc = json.loads(out_file.read_text(encoding="utf-8"))
    ev = json.loads(ev_file.read_text(encoding="utf-8"))

    # Verify strictly against contract rules
    out_errs = cm.check_output("M1", doc)
    assert not out_errs, f"Contract output errors: {out_errs}"

    ev_errs = cm.check_event("M1", ev)
    assert not ev_errs, f"Contract event errors: {ev_errs}"


def test_cli_execution_uniform_flags(tmp_path):
    aid = str(uuid.uuid4())
    vid = str(uuid.uuid4())
    out_file = tmp_path / "contract_out" / "sample.json"

    cmd = [
        sys.executable,
        "-m",
        "m1_ingestion.cli",
        "--analysis-id",
        aid,
        "--vault-id",
        vid,
        "--out",
        str(out_file),
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"CLI failed: {res.stderr}"
    assert out_file.exists()

    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert doc["sample"]["vault_id"] == vid

    out_errs = cm.check_output("M1", doc)
    assert not out_errs, f"Contract output errors: {out_errs}"

