"""M6 CLI coverage: it plans from a document it was given, and refuses when there is none."""
import json
import os
import subprocess
import sys
import uuid

import pytest

from m6_response.cli import create_response_done_event

EXAMPLE = "contract/examples/valid_synthetic_trojan_record.json"


def _run(*extra, out_file=None):
    return subprocess.run(
        [sys.executable, "-m", "m6_response.cli", *extra],
        capture_output=True,
        text=True,
    )


def test_m6_cli_plans_from_an_explicit_document(tmp_path):
    out_file = tmp_path / "nested" / "out_actions.json"
    event_file = tmp_path / "events" / "response_done.json"

    res = _run(
        "--input", EXAMPLE,
        "--out", str(out_file),
        "--event-out", str(event_file),
    )
    assert res.returncode == 0, res.stderr

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(data["response_actions"], list)
    assert len(data["response_actions"]) > 0

    event = json.loads(event_file.read_text(encoding="utf-8"))
    example = json.loads(open(EXAMPLE, encoding="utf-8").read())
    assert event["analysis_id"] == example["analysis_id"]
    assert event["vault_id"] == example["sample"]["vault_id"]
    assert event["payload"]["action_count"] == len(data["response_actions"])
    assert event["payload"]["awaiting_approval"] == sum(
        1 for a in data["response_actions"] if a.get("status") == "awaiting_approval"
    )


def test_m6_cli_requires_exactly_one_document_source(tmp_path):
    out_file = tmp_path / "out.json"
    assert _run("--out", str(out_file)).returncode == 2
    assert _run("--input", EXAMPLE, "--analysis-id", str(uuid.uuid4()), "--out", str(out_file)).returncode == 2
    assert not out_file.exists()


def test_m6_cli_does_not_fall_back_to_the_contract_example(tmp_path):
    """An unknown analysis id must not silently plan against a synthetic sample."""
    from sqlalchemy import create_engine

    from m7_core.database import init_db

    out_file = tmp_path / "out.json"
    db_url = f"sqlite:///{(tmp_path / 'm6_cli.db').as_posix()}"
    init_db(create_engine(db_url, connect_args={"check_same_thread": False}))

    res = subprocess.run(
        [
            sys.executable, "-m", "m6_response.cli",
            "--analysis-id", str(uuid.uuid4()),
            "--out", str(out_file),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "DATABASE_URL": db_url},
    )
    assert res.returncode == 1
    assert "not recorded" in res.stderr
    assert not out_file.exists()


def test_event_fails_closed_when_the_document_has_no_ids():
    with pytest.raises(LookupError):
        create_response_done_event({"verdict": {"label": "malicious"}}, [])
