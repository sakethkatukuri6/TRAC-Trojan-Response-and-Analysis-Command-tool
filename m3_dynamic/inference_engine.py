"""M3 dynamic-analysis adapter for a self-hosted CAPEv2 sandbox.

TRAC never pretends that a PE was executed. Runtime telemetry is published only
when an explicitly configured, isolated CAPEv2 service returns it; without that
service the dynamic stage is ``skipped``. The ``_static_capabilities`` field is
private, derived from the submitted bytes, and is what M4/M5 score when no
sandbox ran.

The adapter speaks the documented CAPE REST API only (see CAPE_LOCAL_LAB.md):

    Authorization: Token <TRAC_CAPE_TOKEN>
    GET  {root}/cuckoo/status/                 preflight
    POST {root}/tasks/create/file/             submit the sample
    GET  {root}/tasks/view/{task_id}/          poll the task
    GET  {root}/tasks/report/{task_id}/json    retrieve the JSON report

Every failure path - unreachable host, rejected token, timeout, malformed or
failed report - collapses to ``dynamic.status = "failed"`` with a bounded,
credential-free message.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple
from urllib import error, request
from urllib.parse import urlsplit, urlunsplit


API_PREFIX = "/apiv2"
_API_PREFIX_REPETITION = re.compile(r"(?:/apiv2)+$", re.IGNORECASE)
PREFLIGHT_TIMEOUT_S = 10
REQUEST_TIMEOUT_S = 30
POLL_INTERVAL_S = 5
MAX_ERROR_LEN = 500

# CAPE exposes the API under /apiv2 and authenticates with a per-user token.
_AUTH_SCHEME = "Token"

_URL_CREDENTIALS = re.compile(r"(?<=://)[^/\s@]+@")
# Narrow shapes rather than one greedy "secret" pattern, so ordinary operator
# guidance such as "check the API token" survives sanitising intact.
_AUTH_HEADER_SECRET = re.compile(r"(?i)\bauthorization\s*:\s*\S+(?:\s+\S+)?")
# A bare "Token <secret>" is only scrubbed when the value looks like a credential
# (long and containing a digit), so prose such as "the API token" stays readable.
_BARE_SCHEME_SECRET = re.compile(r"(?i)\b(?:token|bearer)\s+(?=\S*\d)(?=\S{8,})\S+")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(?:password|passwd|secret|api_?key|access_?key)\s*[=:]\s*[^\s,;\"']+")
_SHA256 = re.compile(r"[0-9a-f]{64}")

# Behaviour-log categories already carry the action that was taken, so the
# mapping below renames CAPE's fields instead of guessing at their meaning.
FILE_EVENT_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("created_files", "create"),
    ("written_files", "modify"),
    ("deleted_files", "delete"),
    ("read_files", "read"),
)
REGISTRY_EVENT_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("created_keys", "create"),
    ("written_keys", "modify"),
    ("deleted_keys", "delete"),
    ("read_keys", "read"),
)
_TASK_SUCCEEDED = {"reported", "completed", "success"}
_TASK_FAILED = {"failed", "failed_analysis", "failed_processing", "report_failed", "recovered"}
_ISOLATED_ROUTES = {"", "none", "drop"}


class CapeError(RuntimeError):
    """A CAPE failure whose message is safe to show an operator."""


class CapeConfigError(CapeError):
    """TRAC_CAPE_URL is not a usable CAPE API endpoint."""


BEHAVIOR_RULES: Dict[str, Dict[str, Any]] = {
    "injection": {"att_id": "T1055", "tactic": "defense-evasion", "description": "Process injection capability", "keywords": ("createremotethread", "virtualallocex", "writeprocessmemory", "ntmapviewofsection", "queueuserapc", "setthreadcontext", "rtlcreateuserthread", "ntcreatethreadex")},
    "persistence": {"att_id": "T1547.001", "tactic": "persistence", "description": "Registry Run Keys / Startup Folder capability", "keywords": ("regsetvalueex", "regcreatekeyex", "currentversion\\run", "currentversion\\runonce", "schtasks", "taskscheduler")},
    "c2_networking": {"att_id": "T1071.001", "tactic": "command-and-control", "description": "Application-layer protocol capability", "keywords": ("internetopen", "internetconnect", "httpsendrequest", "httpopenrequest", "winhttpopen", "winhttpconnect", "wsastartup", "getaddrinfo", "tcpclient", "httpwebrequest")},
    "evasion": {"att_id": "T1497.001", "tactic": "defense-evasion", "description": "Virtualization or debugger discovery capability", "keywords": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "vmware", "virtualbox", "sandboxie", "x64dbg")},
    "keylogging": {"att_id": "T1056.001", "tactic": "collection", "description": "Input-capture capability", "keywords": ("setwindowshookex", "getasynckeystate", "getkeystate", "getkeyboardstate", "keylogger")},
    "credentials": {"att_id": "T1555", "tactic": "credential-access", "description": "Credentials-from-password-stores capability", "keywords": ("credread", "cryptunprotectdata", "vaultcli", "login data", "cookies.sqlite", "logins.json")},
    "screen_capture": {"att_id": "T1113", "tactic": "collection", "description": "Screen-capture capability", "keywords": ("bitblt", "getdc", "getdibits", "printwindow", "copyfromscreen")},
}


def _capabilities(data: bytes, static_result: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return only markers actually present in submitted bytes/imports."""
    tokens: Set[str] = {str(v).lower() for v in static_result.get("pe", {}).get("imports", [])}
    tokens.update(str(v).lower() for v in static_result.get("strings", {}).get("interesting", []))
    # Latin-1 preserves every byte one-to-one while allowing string-marker
    # matching without decoding errors on packed or malformed binaries.
    raw = data.decode("latin-1").lower()
    found: Dict[str, Dict[str, Any]] = {}
    for name, rule in BEHAVIOR_RULES.items():
        matches = [keyword for keyword in rule["keywords"] if keyword in raw or any(keyword in token for token in tokens)]
        if matches:
            found[name] = {"att_id": rule["att_id"], "tactic": rule["tactic"], "description": rule["description"], "matches": matches}
    return found


def cape_api_root(configured: str) -> str:
    """Normalise TRAC_CAPE_URL to ``<scheme>://<host>[:port]/apiv2``, exactly once.

    Accepts ``http://cape-host:8000`` or ``http://cape-host:8000/apiv2`` and any
    trailing-slash variant, including a reverse-proxy sub-path.
    """
    parsed = urlsplit((configured or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise CapeConfigError(
            "TRAC_CAPE_URL must be an http(s) CAPE API endpoint such as http://cape-host:8000/apiv2"
        )
    path = parsed.path.rstrip("/")
    if _API_PREFIX_REPETITION.search(path):
        path = _API_PREFIX_REPETITION.sub(API_PREFIX, path)
    else:
        path = path + API_PREFIX
    return urlunsplit((scheme, parsed.netloc, path, "", ""))


def _multipart_file(data: bytes, filename: str) -> Tuple[bytes, str]:
    boundary = "----trac-" + uuid.uuid4().hex
    safe_name = filename.replace('"', "_").replace("\\", "_").replace("\r", "_").replace("\n", "_")
    body = b"\r\n".join((f"--{boundary}".encode(), f'Content-Disposition: form-data; name="file"; filename="{safe_name}"'.encode(), b"Content-Type: application/octet-stream", b"", data, f"--{boundary}--".encode(), b""))
    return body, boundary


def _redact(text: str, token: Optional[str] = None) -> str:
    """Strip URL credentials and any bearer-style secret from a message."""
    cleaned = _URL_CREDENTIALS.sub("", text)
    cleaned = _AUTH_HEADER_SECRET.sub("[redacted]", cleaned)
    cleaned = _BARE_SCHEME_SECRET.sub("[redacted]", cleaned)
    cleaned = _SECRET_ASSIGNMENT.sub("[redacted]", cleaned)
    if token:
        cleaned = cleaned.replace(token, "[redacted]")
    return cleaned


def _http_failure(exc: error.HTTPError, path: str) -> CapeError:
    code = getattr(exc, "code", None)
    if code in (401, 403):
        return CapeError(f"CAPE rejected the API token for {path} (HTTP {code}); check TRAC_CAPE_TOKEN")
    if code == 404:
        return CapeError(f"CAPE has no endpoint at {path} (HTTP 404); check TRAC_CAPE_URL")
    return CapeError(f"CAPE responded with HTTP {code} for {path}")


def _transport_failure(exc: BaseException, path: str, timeout: int) -> CapeError:
    if isinstance(exc, (TimeoutError, socket.timeout)) or isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
        return CapeError(f"CAPE request to {path} exceeded its {timeout} second timeout")
    if isinstance(exc, http.client.HTTPException):
        return CapeError(f"CAPE closed the HTTP connection during {path}")
    return CapeError(f"CAPE endpoint is unreachable at {path}: {exc}")


def _decode(payload: bytes, path: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CapeError(f"CAPE returned a malformed (non-JSON) response for {path}: {exc}") from None
    if not isinstance(parsed, dict):
        raise CapeError(f"CAPE returned an unexpected response shape for {path}")
    if parsed.get("success") is False or parsed.get("error") is True:
        reason = parsed.get("message") or parsed.get("detail") or "no reason given"
        raise CapeError(f"CAPE refused {path}: {reason}")
    return parsed


def _cape_request(root: str, path: str, token: Optional[str], body: Optional[bytes] = None, content_type: Optional[str] = None, timeout: int = REQUEST_TIMEOUT_S) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"{_AUTH_SCHEME} {token}"
    if content_type:
        headers["Content-Type"] = content_type
    req = request.Request(f"{root}{path}", data=body, headers=headers, method="POST" if body is not None else "GET")
    try:
        with request.urlopen(req, timeout=timeout) as response:  # nosec B310: explicit operator-configured endpoint
            raw = response.read()
    except error.HTTPError as exc:
        raise _http_failure(exc, path) from None
    except (OSError, http.client.HTTPException) as exc:
        raise _transport_failure(exc, path, timeout) from None
    return _decode(raw, path)


def _cape_preflight(root: str, token: Optional[str]) -> None:
    """One bounded status call: proves the API is reachable and the token works."""
    status = _cape_request(root, "/cuckoo/status/", token, timeout=PREFLIGHT_TIMEOUT_S)
    if not (isinstance(status.get("data"), Mapping) or status.get("version") or status.get("machines")):
        raise CapeError("CAPE status response did not describe the analysis service")


def _task_id(created: Mapping[str, Any]) -> str:
    """CAPE returns ``task_id`` for a single submission and ``task_ids`` for a batch."""
    task_id = created.get("task_id") or created.get("task_ids")
    if isinstance(task_id, (list, tuple)):
        task_id = task_id[0] if task_id else None
    return str(task_id) if isinstance(task_id, (int, str)) and str(task_id) else ""


def _task_status(root: str, token: Optional[str], task_id: str) -> str:
    view = _cape_request(root, f"/tasks/view/{task_id}/", token)
    task = view.get("task")
    if not isinstance(task, Mapping):
        raise CapeError(f"CAPE task view did not describe task {task_id}")
    return str(task.get("status", "")).lower()


def _await_report(root: str, token: Optional[str], task_id: str, timeout_s: int) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while True:
        status = _task_status(root, token, task_id)
        if status in _TASK_SUCCEEDED:
            return _cape_request(root, f"/tasks/report/{task_id}/json", token)
        if status in _TASK_FAILED:
            raise CapeError(f"CAPE task {task_id} ended with status '{status}'")
        if time.monotonic() >= deadline:
            raise CapeError(f"CAPE task {task_id} did not reach a terminal status within the {timeout_s} second timeout")
        time.sleep(POLL_INTERVAL_S)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _categorised_events(processes: List[Any], fields: Tuple[Tuple[str, str], ...]) -> List[Dict[str, Any]]:
    """Emit file/registry events only for categories CAPE actually logged."""
    events: List[Dict[str, Any]] = []
    for proc in processes:
        proc = _mapping(proc)
        pid = proc.get("process_id")
        for field, action in fields:
            for target in _list(proc.get(field)):
                if not isinstance(target, (str, int)) or not str(target).strip():
                    continue
                event: Dict[str, Any] = {"action": action, "target": str(target)}
                if isinstance(pid, int) and not isinstance(pid, bool):
                    event["pid"] = pid
                events.append(event)
    return events


def _process_tree(processes: List[Any]) -> List[Dict[str, Any]]:
    tree: List[Dict[str, Any]] = []
    for proc in processes:
        proc = _mapping(proc)
        name = proc.get("process_name")
        pid = proc.get("process_id")
        if not isinstance(pid, int) or isinstance(pid, bool) or not isinstance(name, str):
            continue
        entry: Dict[str, Any] = {"pid": pid, "name": name}
        ppid = proc.get("parent_id")
        if isinstance(ppid, int) and not isinstance(ppid, bool):
            entry["ppid"] = ppid
        command_line = proc.get("command_line")
        if isinstance(command_line, str) and command_line:
            entry["command_line"] = command_line
        tree.append(entry)
    return tree


def _api_summary(processes: List[Any]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for proc in processes:
        for call in _list(_mapping(proc).get("calls")):
            api = _mapping(call).get("api")
            if isinstance(api, str) and api:
                summary[api] = summary.get(api, 0) + 1
    return summary


def _dropped_files(report: Mapping[str, Any]) -> List[Dict[str, Any]]:
    dropped: List[Dict[str, Any]] = []
    for item in _list(report.get("dropped")):
        item = _mapping(item)
        sha256 = str(item.get("sha256") or "").lower()
        if not _SHA256.fullmatch(sha256):
            continue
        entry: Dict[str, Any] = {"sha256": sha256}
        if isinstance(item.get("name"), str) and item["name"]:
            entry["name"] = item["name"]
        size = item.get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            entry["size_bytes"] = size
        dropped.append(entry)
    return dropped


def _network_summary(report: Mapping[str, Any]) -> Optional[Dict[str, int]]:
    network = report.get("network")
    if not isinstance(network, Mapping):
        return None
    return {
        "dns_queries": len(_list(network.get("dns"))),
        "http_requests": len(_list(network.get("http"))),
        "tcp_connections": len(_list(network.get("tcp"))),
    }


def _guest_os(info: Mapping[str, Any]) -> str:
    name = _mapping(info.get("machine")).get("name")
    return str(name) if name else "unknown"


def _network_mode(info: Mapping[str, Any]) -> str:
    """CAPE's route field decides whether the guest was isolated."""
    route = str(info.get("route") or "").strip().lower()
    if route in _ISOLATED_ROUTES:
        return "isolated"
    raise CapeError(
        f"CAPE guest '{route}' is not an isolated network route; TRAC refuses results "
        "from a sandbox that could reach the real internet"
    )


def _reverted() -> bool:
    """Snapshot reversion is an operator attestation, never an assumption."""
    return os.getenv("TRAC_CAPE_SNAPSHOT_REVERTED", "").strip().lower() in {"1", "true", "yes", "on"}


def _normalise_cape_report(report: Mapping[str, Any], task_id: str, timeout_s: int) -> Dict[str, Any]:
    info = _mapping(report.get("info"))
    behavior = _mapping(report.get("behavior"))
    processes = _list(behavior.get("processes"))
    sandbox: Dict[str, Any] = {
        "engine": "capev2",
        "guest_os": _guest_os(info),
        "run_id": task_id,
        "timeout_s": timeout_s,
        "network_mode": _network_mode(info),
        "reverted": _reverted(),
    }
    if not sandbox["reverted"]:
        raise CapeError(
            "CAPE did not confirm snapshot reversion and the operator has not attested it; "
            "set TRAC_CAPE_SNAPSHOT_REVERTED=true only after verifying the guest reverted"
        )
    duration = info.get("duration")
    if isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration >= 0:
        sandbox["duration_s"] = int(duration)

    summary = _mapping(behavior.get("summary"))
    normalised: Dict[str, Any] = {
        "status": "done",
        "sandbox": sandbox,
        "process_tree": _process_tree(processes),
        "file_events": _categorised_events(processes, FILE_EVENT_FIELDS),
        "registry_events": _categorised_events(processes, REGISTRY_EVENT_FIELDS),
        "mutexes": [str(m) for m in _list(summary.get("mutexes")) if isinstance(m, (str, int))],
        "dropped_files": _dropped_files(report),
        "api_summary": _api_summary(processes),
    }
    network = _network_summary(report)
    if network is not None:
        normalised["network_summary"] = network
    return normalised


def _safe_error(exc: BaseException, token: Optional[str] = None) -> str:
    """Return a bounded, credential-free operator-facing error message."""
    return _redact(str(exc), token).strip()[:MAX_ERROR_LEN] or "CAPE request failed"


def infer_behavior(data: bytes, file_type: str, static_result: Dict[str, Any], filename: str = "sample.exe", cape_url: Optional[str] = None, cape_token: Optional[str] = None, timeout_s: int = 180) -> Dict[str, Any]:
    """Return observed CAPE telemetry, or explicitly skip an unconfigured sandbox."""
    capabilities = _capabilities(data, static_result) if file_type == "pe" else {}
    endpoint = cape_url or os.getenv("TRAC_CAPE_URL")
    token = cape_token or os.getenv("TRAC_CAPE_TOKEN")
    if not endpoint or not endpoint.strip():
        return {"status": "skipped", "_static_capabilities": capabilities}
    try:
        root = cape_api_root(endpoint)
        _cape_preflight(root, token)
        body, boundary = _multipart_file(data, filename)
        created = _cape_request(root, "/tasks/create/file/", token, body=body, content_type=f"multipart/form-data; boundary={boundary}")
        task_id = _task_id(created)
        if not task_id:
            raise CapeError("CAPE accepted the submission but returned no task id")
        report = _await_report(root, token, task_id, timeout_s)
        observed = _normalise_cape_report(report, task_id, timeout_s)
        observed["_static_capabilities"] = capabilities
        return observed
    except Exception as exc:  # fail closed: a sandbox we cannot trust yields no dynamic claims
        return {"status": "failed", "_static_capabilities": capabilities, "_error": _safe_error(exc, token)}
