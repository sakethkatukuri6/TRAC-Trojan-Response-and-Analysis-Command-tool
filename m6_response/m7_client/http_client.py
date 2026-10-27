"""HTTP-based M7 client using module bearer token."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional
import httpx
from m6_response.m7_client.client_interface import M7ClientInterface


def get_default_m6_token() -> str:
    from m7_core.api.auth import create_module_token
    return create_module_token("M6")


class HttpM7Client(M7ClientInterface):
    def __init__(self, base_url: str = "http://localhost:8000", token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token or os.getenv("M6_MODULE_TOKEN") or get_default_m6_token()

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def fetch_analysis(self, analysis_id: str) -> Dict[str, Any]:
        with httpx.Client(base_url=self.base_url) as client:
            resp = client.get(f"/api/v1/analyses/{analysis_id}", headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    def submit_section(self, analysis_id: str, section: str, payload: Any) -> Dict[str, Any]:
        with httpx.Client(base_url=self.base_url) as client:
            resp = client.put(f"/api/v1/analyses/{analysis_id}/sections/{section}", json=payload, headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    def emit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with httpx.Client(base_url=self.base_url) as client:
            resp = client.post("/api/v1/events", json=event, headers=self.headers)
            resp.raise_for_status()
            return resp.json()
