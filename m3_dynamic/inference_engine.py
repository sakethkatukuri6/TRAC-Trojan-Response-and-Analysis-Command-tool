"""M3 dynamic-analysis integration and conservative static capability evidence.

TRAC never pretends that a PE was executed. A report contains runtime events
only after they are returned by an explicitly configured, isolated CAPEv2
service. Without that service the dynamic stage is ``skipped``; the private
``_static_capabilities`` field is for downstream in-process evidence scoring.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Set
from urllib import error, request


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


def _multipart_file(data: bytes, filename: str) -> tuple[bytes, str]:
    boundary = "----trac-" + uuid.uuid4().hex
    safe_name = filename.replace('"', "_").replace("\\", "_")
    body = b"\r\n".join((f"--{boundary}".encode(), f'Content-Disposition: form-data; name="file"; filename="{safe_name}"'.encode(), b"Content-Type: application/octet-stream", b"", data, f"--{boundary}--".encode(), b""))
    return body, boundary


def _cape_request(url: str, token: Optional[str], body: Optional[bytes] = None, content_type: Optional[str] = None) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    req = request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    with request.urlopen(req, timeout=30) as response:  # nosec B310: explicit operator-configured endpoint
        return json.loads(response.read().decode("utf-8"))


def _normalise_cape_report(report: Mapping[str, Any], task_id: str, timeout_s: int) -> Dict[str, Any]:
    behavior = report.get("behavior", {}) if isinstance(report.get("behavior"), Mapping) else {}
    processes = behavior.get("processes", []) if isinstance(behavior.get("processes"), list) else []
    process_tree: List[Dict[str, Any]] = []
    api_summary: Dict[str, int] = {}
    for proc in processes:
        if not isinstance(proc, Mapping):
            continue
        process_tree.append({"pid": int(proc.get("process_id", 0)), "ppid": int(proc.get("parent_id", 0)), "name": str(proc.get("process_name", "unknown")), "command_line": str(proc.get("command_line", ""))})
        for call in proc.get("calls", []) if isinstance(proc.get("calls"), list) else []:
            if isinstance(call, Mapping) and call.get("api"):
                api = str(call["api"])
                api_summary[api] = api_summary.get(api, 0) + 1
    summary = behavior.get("summary", {}) if isinstance(behavior.get("summary"), Mapping) else {}
    network = report.get("network", {}) if isinstance(report.get("network"), Mapping) else {}
    info = report.get("info", {}) if isinstance(report.get("info"), Mapping) else {}
    machine = info.get("machine", {}) if isinstance(info.get("machine"), Mapping) else {}
    return {"status": "done", "sandbox": {"engine": "capev2", "guest_os": str(machine.get("name", "unknown")), "run_id": task_id, "duration_s": int(info.get("duration", 0)), "timeout_s": timeout_s, "network_mode": "simulated_internet", "reverted": True}, "process_tree": process_tree, "file_events": [{"action": "create", "target": str(v)} for v in summary.get("write_files", [])], "registry_events": [{"action": "modify", "target": str(v)} for v in summary.get("write_keys", [])], "mutexes": [str(v) for v in summary.get("mutexes", [])], "dropped_files": [], "api_summary": api_summary, "network_summary": {"dns_queries": len(network.get("dns", [])), "http_requests": len(network.get("http", [])), "tcp_connections": len(network.get("tcp", []))}}


def _submit_to_cape(data: bytes, filename: str, base_url: str, token: Optional[str], timeout_s: int) -> Dict[str, Any]:
    root = base_url.rstrip("/")
    body, boundary = _multipart_file(data, filename)
    created = _cape_request(f"{root}/tasks/create/file/", token, body, f"multipart/form-data; boundary={boundary}")
    ids = created.get("task_ids", [])
    task_id = str(created.get("task_id") or (ids[0] if ids else ""))
    if not task_id:
        raise RuntimeError("CAPE did not return a task id")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        view = _cape_request(f"{root}/tasks/view/{task_id}/", token)
        status = str(view.get("task", {}).get("status", "")).lower()
        if status in {"reported", "completed"}:
            return _normalise_cape_report(_cape_request(f"{root}/tasks/report/{task_id}/json", token), task_id, timeout_s)
        if status in {"failed", "recovered"}:
            raise RuntimeError(f"CAPE task {task_id} ended with status {status}")
        time.sleep(5)
    raise TimeoutError(f"CAPE task {task_id} did not finish within {timeout_s} seconds")


def infer_behavior(data: bytes, file_type: str, static_result: Dict[str, Any], filename: str = "sample.exe", cape_url: Optional[str] = None, cape_token: Optional[str] = None, timeout_s: int = 180) -> Dict[str, Any]:
    """Return observed CAPE telemetry, or explicitly skip an unconfigured sandbox."""
    capabilities = _capabilities(data, static_result) if file_type == "pe" else {}
    endpoint = cape_url or os.getenv("TRAC_CAPE_URL")
    token = cape_token or os.getenv("TRAC_CAPE_TOKEN")
    if not endpoint:
        return {"status": "skipped", "_static_capabilities": capabilities}
    try:
        observed = _submit_to_cape(data, filename, endpoint, token, timeout_s)
        observed["_static_capabilities"] = capabilities
        return observed
    except (error.URLError, error.HTTPError, ValueError, RuntimeError, TimeoutError) as exc:
        return {"status": "failed", "_static_capabilities": capabilities, "_error": str(exc)[:500]}
