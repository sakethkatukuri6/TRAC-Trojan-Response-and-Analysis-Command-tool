"""Test health endpoints."""
from m7_core.api.app import app
from m7_core.database import get_db


def test_root_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_api_v1_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["db"] == "ok"


def test_api_v1_health_reports_unhealthy_when_the_database_fails(client):
    class BrokenSession:
        def execute(self, *args, **kwargs):
            raise RuntimeError("database is down")

    app.dependency_overrides[get_db] = lambda: BrokenSession()
    try:
        response = client.get("/api/v1/health")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "unhealthy"
    assert "database is down" in data["db"]
