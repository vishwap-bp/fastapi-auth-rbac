"""tests/test_logout.py — Logout endpoint tests."""


def test_logout_success(client, user_tokens, auth_headers):
    resp = client.post(
        "/auth/logout",
        json={"refresh_token": user_tokens["refresh_token"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "Logged out" in resp.json()["message"]


def test_logout_revokes_refresh_token(client, user_tokens, auth_headers):
    """After logout, the refresh token must be rejected."""
    client.post(
        "/auth/logout",
        json={"refresh_token": user_tokens["refresh_token"]},
        headers=auth_headers,
    )
    # Attempt to use the revoked refresh token
    resp = client.post("/auth/refresh", json={"refresh_token": user_tokens["refresh_token"]})
    assert resp.status_code == 401


def test_logout_requires_auth(client, user_tokens):
    """Logout without Authorization header should fail."""
    resp = client.post("/auth/logout", json={"refresh_token": user_tokens["refresh_token"]})
    # HTTPBearer returns 401
    assert resp.status_code in (401, 403)
