"""Shared Prometheus metrics for the M7 API and the M8 console.

The devops/prometheus/alerts.yml rules reference these metric names; keep them
in sync when renaming. HTTP path labels are normalised (UUIDs and long hex
strings masked) so that per-analysis routes do not explode cardinality.
"""
from __future__ import annotations

import re
import time
from typing import Callable

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.requests import Request
from starlette.responses import Response

HTTP_REQUESTS = Counter(
    "trac_http_requests_total",
    "HTTP requests handled by the platform, by method, route pattern and status.",
    ["service", "method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "trac_http_request_latency_seconds",
    "HTTP request latency in seconds, by service and route pattern.",
    ["service", "method", "path"],
)
STAGE_FAILURES = Counter(
    "trac_stage_failures_total",
    "Analysis pipeline stages that reported a failure, by stage name.",
    ["stage"],
)
ANALYSES = Counter(
    "trac_analyses_total",
    "Completed pipeline analyses, by verdict label.",
    ["verdict"],
)

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")


def normalise_path(path: str) -> str:
    path = _UUID_RE.sub(":id", path)
    path = _HEX_RE.sub(":hash", path)
    return path


def metrics_endpoint(request: Request) -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


def install_metrics_middleware(app, service: str) -> None:
    @app.middleware("http")
    async def track_requests(request: Request, call_next: Callable):
        path = normalise_path(request.url.path)
        method = request.method
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            HTTP_REQUESTS.labels(service, method, path, "500").inc()
            HTTP_LATENCY.labels(service, method, path).observe(time.perf_counter() - start)
            raise
        elapsed = time.perf_counter() - start
        HTTP_REQUESTS.labels(service, method, path, str(response.status_code)).inc()
        HTTP_LATENCY.labels(service, method, path).observe(elapsed)
        return response
