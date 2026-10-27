"""CSV Exporter for M6."""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List


def export_csv(response_actions: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["action_id", "type", "target", "mode", "status", "playbook", "approval_required"])

    for a in response_actions:
        writer.writerow([
            a.get("action_id"),
            a.get("type"),
            a.get("target"),
            a.get("mode"),
            a.get("status"),
            a.get("playbook"),
            a.get("approval", {}).get("required", False)
        ])

    return output.getvalue()
