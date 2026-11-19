"""HTTP-based M7 client using module bearer token with connection pooling and retries."""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Dict, Optional, TypeVar
import httpx
from m6_response.m7_client.client_interface import M7ClientInterface
from m7_core.contract.loader import get_m7_base_url

logger = logging.getLogger("m6_response.http_client")
T = TypeVar("T")


def get_default_m6_token() -> str:
    from m7_core.api.auth import create_module_token
    return create_module_token("M6")


class HttpM7Client(M7ClientInterface):
    """Resilient HTTP client for M6 -> M7 communication.

    Uses a persistent httpx.Client with connection pooling, keepalive, and
    exponential retry backoff on transient connection failures.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        # M7_API_URL lets a deployment point M6 at a different host without editing
        # code; otherwise the origin openapi.yaml publishes is used.
        self.base_url = (base_url or os.getenv("M7_API_URL") or get_m7_base_url()).rstrip("/")
        self.token = token or os.getenv("M6_MODULE_TOKEN") or get_default_m6_token()
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        limits = httpx.Limits(
            max_keepalive_connections=10,
            max_connections=20,
            keepalive_expiry=30.0,
        )
        self._client: Optional[httpx.Client] = httpx.Client(
            base_url=self.base_url,
            limits=limits,
            timeout=httpx.Timeout(self.timeout, connect=3.0),
        )

    @property
    def client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(
                max_keepalive_connections=10,
                max_connections=20,
                keepalive_expiry=30.0,
            )
            self._client = httpx.Client(
                base_url=self.base_url,
                limits=limits,
                timeout=httpx.Timeout(self.timeout, connect=3.0),
            )
        return self._client

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _execute_with_retry(self, fn: Callable[[httpx.Client], httpx.Response]) -> Dict[str, Any]:
        """Execute an HTTP request with exponential backoff on transient failures."""
        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                resp = fn(self.client)
                resp.raise_for_status()
                return resp.json()
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    sleep_time = self.backoff_factor * (2 ** attempt)
                    logger.warning(
                        "Transient HTTP failure (%s) communicating with M7 at %s; retry %d/%d in %.2fs",
                        exc, self.base_url, attempt + 1, self.max_retries, sleep_time,
                    )
                    time.sleep(sleep_time)
                else:
                    logger.error("Exhausted retries connecting to M7 at %s: %s", self.base_url, exc)
            except httpx.HTTPStatusError:
                # HTTP 4xx / 5xx errors from the server are not transient connection issues
                raise
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected retry loop termination")

    def fetch_analysis(self, analysis_id: str) -> Dict[str, Any]:
        return self._execute_with_retry(
            lambda c: c.get(f"/api/v1/analyses/{analysis_id}", headers=self.headers)
        )

    def submit_section(self, analysis_id: str, section: str, payload: Any) -> Dict[str, Any]:
        return self._execute_with_retry(
            lambda c: c.put(
                f"/api/v1/analyses/{analysis_id}/sections/{section}",
                json=payload,
                headers=self.headers,
            )
        )

    def emit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute_with_retry(
            lambda c: c.post("/api/v1/events", json=event, headers=self.headers)
        )

    def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            self._client.close()

    def __enter__(self) -> HttpM7Client:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
