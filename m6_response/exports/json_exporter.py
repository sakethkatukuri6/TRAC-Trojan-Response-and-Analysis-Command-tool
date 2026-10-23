"""JSON Exporter for M6."""
from __future__ import annotations

import json
from typing import Any, Dict, List


def export_json(response_actions: List[Dict[str, Any]]) -> str:
    return json.dumps({"response_actions": response_actions}, indent=2)
