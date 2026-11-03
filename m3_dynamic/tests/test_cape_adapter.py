"""Mocked-HTTP integration tests for the M3 CAPEv2 adapter.

Nothing here talks to a real sandbox and nothing here executes a sample: the
adapter's only network primitive (``urllib.request``) is replaced by a fake
transport that records every outbound request and replays canned CAPE replies.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib import error as _error
from urllib import request as _real_request
from urllib.parse import urlparse

import pytest

from m3_dynamic import inference_engine as ie

TOKEN = "cape-token-3f9c1f"
BASE = "http://cape.test:8000"

STATUS_PATH = "/apiv2/cuckoo/status/"
CREATE_PATH = "/apiv2/tasks/create/file/"
REPORT_PATH = "/apiv2/tasks/report/4210/json"

CAPE_STATUS = {"success": True, "message": "Status obtained", "data": {"version": "2.4-CAPE", "machines": {"total": 2, "running": 0, "free": 2}, "queues": {"pending": 0, "processing": 0, "completed": 11}}}

CAPE_TASK_VIEW_RUNNING = {"success": True, "task": {"id": 4210, "status": "running"}}
CAPE_TASK_VIEW_REPORTED = {"success": True, "task": {"id": 4210, "status": "reported"}}
CAPE_TASK_CREATED = {"task_ids": [4210], "messages": [{"task_ids": [4210], "messages": []}]}

SHA256_A = "a" * 64

CAPE_REPORT = {
    "info": {
        "id": 4210,
        "duration": 118,
        "route": "none",
        "machine": {"id": 1, "name": "win10x64-1", "platform": "windows"},
    },
    "behavior": {
        "processes": [
            {
                "process_id": 2100,
                "parent_id": 900,
                "process_name": "sample.exe",
                "command_line": "sample.exe --silent",
                "calls": [
                    {"api": "CreateFileW"},
                    {"api": "CreateFileW"},
                    {"api": "InternetOpenW"},
                ],
                "created_files": ["C:\\Users\\Public\\drop.bin"],
                "written_files": ["C:\\Users\\Public\\config.dat"],
                "read_files": ["C:\\Windows\\System32\\kernel32.dll"],
                "deleted_files": [],
                "written_keys": ["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Svc"],
            },
            {
                "process_id": 2144,
                "parent_id": 2100,
                "process_name": "cmd.exe",
                "calls": [{"api": "CreateMutexW"}],
            },
        ],
        "summary": {"mutexes": ["Global\\TRAC_MTX"]},
    },
    "network": {
        "dns": [{"request": "evil.example"}],
        "http": [{"method": "GET"}],
        "tcp": [{"src": "10.0.0.5", "dst": "198.51.100.9"}],
    },
    "dropped": [
        {"name": "drop.bin", "sha256": SHA256_A, "size": 512, "path": "/opt/CAPEv2/storage/.../drop.bin"},
        {"name": "no-hash.bin", "size": 10},
    ],
}


class FakeResponse:
    def __init__(self, payload, status: int = 200):
        self.status = status
        self._body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeCAPE:
    """Stand-in for ``urllib.request``: records requests, replays scripted replies."""

    Request = _real_request.Request

    def __init__(self, script):
        self.script = {(method, path): list(outcomes) for (method, path), outcomes in script.items()}
        self.calls: list[dict] = []

    def urlopen(self, req, timeout=None):
        path = urlparse(req.full_url).path
        self.calls.append(
            {
                "method": req.get_method(),
                "url": req.full_url,
                "path": path,
                "headers": {k.lower(): v for k, v in req.header_items()},
                "body": req.data,
                "timeout": timeout,
            }
        )
        key = (req.get_method(), path)
        if key not in self.script:
            raise AssertionError(f"unexpected CAPE request: {key[0]} {key[1]}")
        outcomes = self.script[key]
        outcome = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome if isinstance(outcome, FakeResponse) else FakeResponse(outcome)

    def paths(self):
        return [(call["method"], call["path"]) for call in self.calls]

    def header(self, index: int, name: str):
        return self.calls[index]["headers"].get(name.lower())


@pytest.fixture
def transport(monkeypatch):
    def _install(script):
        fake = FakeCAPE(script)
        monkeypatch.setattr(ie, "request", fake)
        return fake

    return _install


@pytest.fixture
def clock(monkeypatch):
    """Deterministic time so polling never sleeps for real."""

    class FakeTime:
        def __init__(self):
            self.now = 1_000.0
            self.slept = []

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.slept.append(seconds)
            self.now += seconds

    fake = FakeTime()
    monkeypatch.setattr(ie, "time", fake)
    return fake


@pytest.fixture
def lab(monkeypatch):
    """A configured, operator-attested lab: token present and snapshot revert verified."""
    monkeypatch.delenv("TRAC_CAPE_URL", raising=False)
    monkeypatch.delenv("TRAC_CAPE_TOKEN", raising=False)
    monkeypatch.setenv("TRAC_CAPE_SNAPSHOT_REVERTED", "true")
    return monkeypatch


def run_adapter(cape_url=BASE, **kwargs):
    kwargs.setdefault("cape_token", TOKEN)
    return ie.infer_behavior(
        data=b"MZ fake bytes",
        file_type="pe",
        static_result={"pe": {"imports": ["kernel32.dll:CreateRemoteThread"]}, "strings": {"interesting": []}},
        filename="sample.exe",
        cape_url=cape_url,
        **kwargs,
    )


# --- 1. URL normalisation -----------------------------------------------------


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("http://cape-host:8000", "http://cape-host:8000/apiv2"),
        ("http://cape-host:8000/", "http://cape-host:8000/apiv2"),
        ("http://cape-host:8000/apiv2", "http://cape-host:8000/apiv2"),
        ("http://cape-host:8000/apiv2/", "http://cape-host:8000/apiv2"),
        ("HTTP://cape-host:8000/apiv2///", "http://cape-host:8000/apiv2"),
        ("https://cape-host:8000/apiv2", "https://cape-host:8000/apiv2"),
        ("http://cape-host:8000/cape/apiv2/", "http://cape-host:8000/cape/apiv2"),
        ("http://cape-host:8000/apiv2/apiv2", "http://cape-host:8000/apiv2"),
        ("http://cape-host:8000/APIv2", "http://cape-host:8000/apiv2"),
    ],
)
def test_api_root_is_normalised_with_exactly_one_apiv2_prefix(configured, expected):
    assert ie.cape_api_root(configured) == expected


@pytest.mark.parametrize("configured", ["cape-host:8000", "ftp://cape-host:8000", "http://", "http:///apiv2", "not a url"])
def test_invalid_cape_url_fails_closed_without_calling_anything(configured, transport, lab):
    fake = transport({})
    result = run_adapter(cape_url=configured)

    assert result["status"] == "failed"
    assert "sandbox" not in result
    assert fake.calls == []


@pytest.mark.parametrize("configured", ["", "   "])
def test_blank_cape_url_counts_as_unconfigured_and_is_skipped(configured, transport, lab):
    fake = transport({})
    result = run_adapter(cape_url=configured)

    assert result["status"] == "skipped"
    assert fake.calls == []


def test_configured_url_is_used_for_every_documented_apiv2_endpoint(transport, lab, clock):
    fake = transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_RUNNING, CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    run_adapter(cape_url=BASE)

    assert all(call["url"].startswith(f"{BASE}/apiv2/") for call in fake.calls)
    assert ie.cape_api_root(BASE) == f"{BASE}/apiv2"


# --- 2. Token authentication --------------------------------------------------


def test_every_request_uses_cape_documented_token_header(transport, lab, clock):
    fake = transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    run_adapter()

    assert fake.calls, "adapter made no request"
    for call in fake.calls:
        assert call["headers"]["authorization"] == f"Token {TOKEN}"


def test_absent_token_sends_no_authorization_header(transport, lab, clock):
    lab.delenv("TRAC_CAPE_TOKEN", raising=False)
    fake = transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    run_adapter(cape_token=None)

    assert all("authorization" not in call["headers"] for call in fake.calls)


def test_file_upload_uses_multipart_file_field_and_bounded_timeouts(transport, lab, clock):
    fake = transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    run_adapter(timeout_s=90)

    submission = next(call for call in fake.calls if call["path"] == CREATE_PATH)
    assert submission["method"] == "POST"
    assert submission["headers"]["content-type"].startswith("multipart/form-data; boundary=")
    assert b'name="file"; filename="sample.exe"' in submission["body"]
    assert b"MZ fake bytes" in submission["body"]
    for call in fake.calls:
        assert isinstance(call["timeout"], (int, float)) and 0 < call["timeout"] <= 30


# --- 3. Preflight -------------------------------------------------------------


def test_preflight_hits_the_status_endpoint_once_before_submitting(transport, lab, clock):
    fake = transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    run_adapter()

    preflights = [call for call in fake.calls if call["path"] == STATUS_PATH]
    assert len(preflights) == 1
    assert fake.paths()[0] == ("GET", STATUS_PATH)


def test_preflight_rejects_unsuccessful_status_payload(transport, lab, clock):
    fake = transport({("GET", STATUS_PATH): [{"success": False, "message": "scheduler disabled"}]})
    result = run_adapter()

    assert result["status"] == "failed"
    assert ("POST", CREATE_PATH) not in fake.paths()


def test_preflight_rejects_non_json_status_body(transport, lab, clock):
    transport({("GET", STATUS_PATH): [FakeResponse(b"<html>502 Bad Gateway</html>")]})
    result = run_adapter()

    assert result["status"] == "failed"
    assert "<html>" not in result["_error"]


# --- 4/6. Success path: normalisation of returned telemetry -------------------


def test_successful_run_reports_contract_shaped_dynamic_section(transport, lab, clock):
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_RUNNING, CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    result = run_adapter(timeout_s=180)

    assert result["status"] == "done"
    assert result["sandbox"] == {
        "engine": "capev2",
        "guest_os": "win10x64-1",
        "run_id": "4210",
        "duration_s": 118,
        "timeout_s": 180,
        "network_mode": "isolated",
        "reverted": True,
    }
    assert result["process_tree"] == [
        {"pid": 2100, "ppid": 900, "name": "sample.exe", "command_line": "sample.exe --silent"},
        {"pid": 2144, "ppid": 2100, "name": "cmd.exe"},
    ]
    assert result["api_summary"] == {"CreateFileW": 2, "InternetOpenW": 1, "CreateMutexW": 1}
    assert result["mutexes"] == ["Global\\TRAC_MTX"]
    assert result["network_summary"] == {"dns_queries": 1, "http_requests": 1, "tcp_connections": 1}
    assert result["dropped_files"] == [{"sha256": SHA256_A, "name": "drop.bin", "size_bytes": 512}]
    assert result["file_events"] == [
        {"action": "create", "target": "C:\\Users\\Public\\drop.bin", "pid": 2100},
        {"action": "modify", "target": "C:\\Users\\Public\\config.dat", "pid": 2100},
        {"action": "read", "target": "C:\\Windows\\System32\\kernel32.dll", "pid": 2100},
    ]
    assert result["registry_events"] == [
        {"action": "modify", "target": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Svc", "pid": 2100}
    ]
    assert result["_static_capabilities"]["injection"]["matches"] == ["createremotethread"]


def test_dynamic_section_validates_against_the_contract(transport, lab):
    import jsonschema

    schema_path = Path(__file__).resolve().parents[2] / "contract" / "schemas" / "analysis_result.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    result = {k: v for k, v in run_adapter().items() if not k.startswith("_")}
    wrapper = {"$defs": schema["$defs"], "type": "object", "properties": {"dynamic": schema["properties"]["dynamic"]}}
    jsonschema.Draft202012Validator(wrapper).validate({"dynamic": result})


def test_telemetry_cape_did_not_return_is_omitted_rather_than_invented(transport, lab, clock):
    bare = {"info": {"id": 4210, "duration": 60, "machine": {"name": "win10x64-1"}}}
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [bare],
        }
    )
    result = run_adapter()

    assert result["status"] == "done"
    assert result["process_tree"] == []
    assert result["file_events"] == []
    assert result["registry_events"] == []
    assert result["mutexes"] == []
    assert result["dropped_files"] == []
    assert result["api_summary"] == {}
    assert "network_summary" not in result, "no network section was returned, so no counts may be claimed"
    assert result["sandbox"]["reverted"] is True


def test_static_capabilities_are_attached_even_without_runtime_telemetry(transport, lab, clock):
    transport({("GET", STATUS_PATH): [_error.URLError("connection refused")]})
    result = run_adapter()

    assert result["status"] == "failed"
    assert set(result["_static_capabilities"]) == {"injection"}


# --- 5. Fail closed -----------------------------------------------------------


def test_connection_refused_fails_closed(transport, lab, clock):
    transport({("GET", STATUS_PATH): [_error.URLError("connection refused")]})
    result = run_adapter()

    assert result["status"] == "failed"
    assert "sandbox" not in result and "process_tree" not in result
    assert result["_error"]


def test_preflight_timeout_fails_closed(transport, lab):
    import socket

    transport({("GET", STATUS_PATH): [socket.timeout("timed out")]})
    result = run_adapter()

    assert result["status"] == "failed"
    assert "timeout" in result["_error"].lower()


def test_http_auth_failure_fails_closed_and_names_the_token_as_cause(transport, lab, clock):
    transport({("GET", STATUS_PATH): [_error.HTTPError(BASE + STATUS_PATH, 401, "UNAUTHORIZED", {}, None)]})
    result = run_adapter()

    assert result["status"] == "failed"
    assert "401" in result["_error"]
    assert "CAPE rejected the API token" in result["_error"], "sanitising must stay readable"
    assert "TRAC_CAPE_TOKEN" in result["_error"]
    assert TOKEN not in result["_error"]


def test_missing_api_token_fails_closed_on_auth_required(transport, lab, clock):
    lab.delenv("TRAC_CAPE_TOKEN", raising=False)
    transport(
        {
            ("GET", STATUS_PATH): [FakeResponse({"detail": "Authentication token required", "error": True}, status=200)],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
        }
    )
    result = run_adapter(cape_token=None)

    assert result["status"] == "failed"


def test_report_failure_fails_closed_even_after_a_completed_task(transport, lab, clock):
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [_error.HTTPError(BASE + REPORT_PATH, 500, "INTERNAL SERVER ERROR", {}, None)],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"
    assert "sandbox" not in result and "process_tree" not in result


def test_malformed_json_success_response_fails_closed(transport, lab, clock):
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [FakeResponse(b'{"info": ')],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"
    assert "sandbox" not in result


def test_task_without_id_fails_closed(transport, lab, clock):
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [{"detail": "unknown error"}],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"
    assert "task id" in result["_error"].lower()


@pytest.mark.parametrize("status", ["failed", "failed_analysis", "report_failed", "recovered"])
def test_terminal_failed_task_statuses_fail_closed(transport, lab, clock, status):
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [{"success": True, "task": {"id": 4210, "status": status}}],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"
    assert status in result["_error"]


def test_poll_deadline_exceeded_fails_closed_without_claiming_results(transport, lab, clock):
    fake = transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_RUNNING],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    result = run_adapter(timeout_s=30)

    assert result["status"] == "failed"
    assert "timeout" in result["_error"].lower()
    assert "sandbox" not in result
    assert ("GET", REPORT_PATH) not in fake.paths(), "a run that never finished has no report to fetch"
    assert clock.now >= 1_000.0 + 30


def test_unexpected_adapter_crash_still_fails_closed(transport, lab, clock):
    class Boom(Exception):
        pass

    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [Boom("tokenizer exploded")],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"
    assert "sandbox" not in result


# --- Error sanitisation -------------------------------------------------------


def test_errors_never_leak_the_token_or_url_credentials(transport, lab, clock):
    secret_url = "http://analyst:s3cret@cape.test:8000"
    transport({("GET", STATUS_PATH): [_error.URLError(f"cannot reach {secret_url} with Authorization: Token {TOKEN}")]})
    result = run_adapter(cape_url=secret_url)

    assert result["status"] == "failed"
    assert "s3cret" not in result["_error"]
    assert TOKEN not in result["_error"]
    assert "analyst:" not in result["_error"]
    assert len(result["_error"]) <= 500


def test_snapshot_reversion_must_be_attested_before_a_run_is_reported_done(transport, lab, clock):
    lab.delenv("TRAC_CAPE_SNAPSHOT_REVERTED")
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"
    assert "revert" in result["_error"].lower()
    assert "sandbox" not in result, "an unverified guest state may never be published as a completed run"


@pytest.mark.parametrize("attestation", ["false", "0", "no", ""])
def test_negative_snapshot_attestation_fails_closed(transport, lab, clock, attestation):
    lab.setenv("TRAC_CAPE_SNAPSHOT_REVERTED", attestation)
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"


@pytest.mark.parametrize("route", ["internet", "tor", "vpn1"])
def test_non_isolated_guest_routing_fails_closed(transport, lab, clock, route):
    report = dict(CAPE_REPORT, info=dict(CAPE_REPORT["info"], route=route))
    transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [report],
        }
    )
    result = run_adapter()

    assert result["status"] == "failed"
    assert route in result["_error"]
    assert "sandbox" not in result


def test_environment_configuration_is_read_when_arguments_are_omitted(transport, lab, clock):
    lab.setenv("TRAC_CAPE_URL", f"{BASE}/apiv2")
    lab.setenv("TRAC_CAPE_TOKEN", TOKEN)
    fake = transport(
        {
            ("GET", STATUS_PATH): [CAPE_STATUS],
            ("POST", CREATE_PATH): [CAPE_TASK_CREATED],
            ("GET", "/apiv2/tasks/view/4210/"): [CAPE_TASK_VIEW_REPORTED],
            ("GET", REPORT_PATH): [CAPE_REPORT],
        }
    )
    result = ie.infer_behavior(b"MZ", "pe", {"pe": {"imports": []}, "strings": {"interesting": []}}, "sample.exe")

    assert result["status"] == "done"
    assert fake.calls[0]["url"] == f"{BASE}{STATUS_PATH}"
