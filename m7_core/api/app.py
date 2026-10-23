"""FastAPI Application factory for M7 Core API."""
from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI
from m7_core.contract.loader import get_openapi_spec
from m7_core.database import init_db
from m7_core.api.routers import health, sections, actions, analyses, events, exports, auth_routes


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    spec = get_openapi_spec()
    info = spec.get("info", {})
    app = FastAPI(
        title=info.get("title", "Malware Analysis Platform API (M7)"),
        version=info.get("version", "1.0.0"),
        description=info.get("description", "M7 Core API and Orchestration"),
        lifespan=lifespan,
    )

    # Mount routers
    app.include_router(health.router)
    app.include_router(sections.router)
    app.include_router(actions.router)
    app.include_router(analyses.router)
    app.include_router(events.router)
    app.include_router(exports.router)
    app.include_router(auth_routes.router)

    return app


app = create_app()
