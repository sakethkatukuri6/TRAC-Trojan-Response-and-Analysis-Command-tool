"""Test authentication and authorization."""
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
