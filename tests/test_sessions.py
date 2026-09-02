"""
tests/test_sessions.py — Session management endpoint tests.

Critical tests per plan: verifies that session table and token table
stay consistent after login, refresh, and logout.
"""
from app.models.token import RefreshToken


def test_list_sessions_after_login(client, user_tokens, auth_headers, db):
    """After login, there should be exactly one active session."""
    resp = client.get("/auth/sessions", headers=auth_headers)
    assert resp.status_code == 200
    sessions = resp.json()["data"]
    assert len(sessions) == 1
    assert sessions[0]["expires_at"] is not None


def test_session_count_after_refresh(client, user_tokens, auth_headers, db):
    """After refresh, there should still be exactly one active session (old revoked)."""
    resp1 = client.post("/auth/refresh", json={"refresh_token": user_tokens["refresh_token"]})
    new_access = resp1.json()["data"]["access_token"]

    resp = client.get("/auth/sessions", headers={"Authorization": f"Bearer {new_access}"})
    sessions = resp.json()["data"]
    # Only the new session should be active — old one is revoked
    assert len(sessions) == 1


def test_revoke_one_session(client, user_tokens, auth_headers, db):
    """Revoke a specific session by ID."""
    sessions_resp = client.get("/auth/sessions", headers=auth_headers)
    session_id = sessions_resp.json()["data"][0]["id"]

    resp = client.delete(f"/auth/sessions/{session_id}", headers=auth_headers)
    assert resp.status_code == 200

    # DB check: token is revoked
    token = db.query(RefreshToken).filter(RefreshToken.id == session_id).first()
    assert token is not None
    assert token.is_revoked is True

    # Session list should now be empty
    list_resp = client.get("/auth/sessions", headers=auth_headers)
    assert list_resp.json()["data"] == []


def test_revoke_all_other_sessions(client, verified_user, db):
    """
    Log in from two 'devices', then revoke all others.
    Consistency check: both DB token table and session API agree on state.
    """
    # Login from device A
    resp_a = client.post("/auth/login", json=verified_user)
    token_a = resp_a.json()["data"]

    # Login from device B
    resp_b = client.post("/auth/login", json=verified_user)
    token_b = resp_b.json()["data"]

    # Device A revokes all other sessions
    resp = client.delete(
        "/auth/sessions",
        headers={"Authorization": f"Bearer {token_a['access_token']}"},
    )
    assert resp.status_code == 200
    assert "1" in resp.json()["message"]  # 1 other session revoked

    # DB consistency check: device B token should be revoked
    from jose import jwt as jose_jwt
    import os
    payload_b = jose_jwt.decode(
        token_b["refresh_token"],
        os.environ["SECRET_KEY"],
        algorithms=["HS256"],
    )
    jti_b = payload_b["jti"]
    token_b_row = db.query(RefreshToken).filter(RefreshToken.jti == jti_b).first()
    assert token_b_row is not None
    assert token_b_row.is_revoked is True

    # Device A's session should still be active
    sessions_a = client.get(
        "/auth/sessions",
        headers={"Authorization": f"Bearer {token_a['access_token']}"},
    )
    assert len(sessions_a.json()["data"]) == 1


def test_revoke_nonexistent_session(client, auth_headers):
    """Revoking a session that doesn't exist or belongs to another user returns 404."""
    resp = client.delete("/auth/sessions/99999", headers=auth_headers)
    assert resp.status_code == 404


def test_session_consistency_after_logout(client, user_tokens, auth_headers, db):
    """
    After logout, token table row is revoked AND session list is empty.
    Verifies both views of truth are consistent.
    """
    from jose import jwt as jose_jwt
    import os
    payload = jose_jwt.decode(
        user_tokens["refresh_token"], os.environ["SECRET_KEY"], algorithms=["HS256"]
    )
    jti = payload["jti"]

    # Logout
    client.post(
        "/auth/logout",
        json={"refresh_token": user_tokens["refresh_token"]},
        headers=auth_headers,
    )

    # DB: token is revoked
    token_row = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()
    assert token_row is not None
    assert token_row.is_revoked is True

    # Session API: list is empty
    list_resp = client.get("/auth/sessions", headers=auth_headers)
    assert list_resp.json()["data"] == []
