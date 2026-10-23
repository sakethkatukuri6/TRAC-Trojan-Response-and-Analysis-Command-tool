"""Test authentication, authorization, and declared bearer security."""
from m7_core.api.auth import verify_password, get_password_hash, create_user_token, create_module_token


def test_password_hashing():
    pw = "SecretP@ssw0rd!"
    h = get_password_hash(pw)
    assert verify_password(pw, h)
    assert not verify_password("wrong", h)


def test_user_login(client):
    resp = client.post("/api/v1/auth/token", json={"username": "analyst_user", "password": "analystpass123"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_invalid_login(client):
    resp = client.post("/api/v1/auth/token", json={"username": "analyst_user", "password": "wrongpassword"})
    assert resp.status_code == 401


def test_public_module_token_route_does_not_exist(client):
    """P0 check: No unauthenticated public route can mint module tokens."""
    resp = client.post("/api/v1/auth/module-token/M6")
    assert resp.status_code in (404, 405)


def test_admin_can_provision_module_token(client, admin_token, analyst_token):
    # Non-admin cannot provision
    resp_analyst = client.post(
        "/api/v1/auth/admin/module-token/M6",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp_analyst.status_code == 403

    # Admin can provision
    resp_admin = client.post(
        "/api/v1/auth/admin/module-token/M6",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp_admin.status_code == 200
    assert "access_token" in resp_admin.json()


def test_declared_bearer_security_enforced_on_analyses(client, analyst_token):
    # Unauthenticated GET /analyses fails with 401
    resp_unauth = client.get("/api/v1/analyses")
    assert resp_unauth.status_code == 401

    # Authenticated GET /analyses succeeds
    resp_auth = client.get("/api/v1/analyses", headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp_auth.status_code == 200
