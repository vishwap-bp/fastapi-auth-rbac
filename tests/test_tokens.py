"""
tests/test_tokens.py — JWT lifecycle, refresh rotation, and replay detection.
"""


def test_refresh_returns_new_tokens(client, user_tokens):
    resp = client.post("/auth/refresh", json={"refresh_token": user_tokens["refresh_token"]})
    assert resp.status_code == 200
    data = resp.json().get("data") or resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    # New tokens must differ from originals
    assert data["access_token"] != user_tokens["access_token"]
    assert data["refresh_token"] != user_tokens["refresh_token"]


def test_old_refresh_token_revoked_after_rotation(client, user_tokens):
    """After refresh, the old refresh token must be rejected."""
    client.post("/auth/refresh", json={"refresh_token": user_tokens["refresh_token"]})
    # Try the old token
    resp = client.post("/auth/refresh", json={"refresh_token": user_tokens["refresh_token"]})
    assert resp.status_code == 401


def test_replay_attack_revokes_entire_family(client, user_tokens, db):
    """
    Replaying a previously used (revoked) refresh token must revoke
    ALL tokens in the same family — not just the replayed one.
    """
    # Step 1: Rotate to get new token
    resp1 = client.post("/auth/refresh", json={"refresh_token": user_tokens["refresh_token"]})
    assert resp1.status_code == 200
    new_refresh = resp1.json()["data"]["refresh_token"]

    # Step 2: Rotate again to get another new token
    resp2 = client.post("/auth/refresh", json={"refresh_token": new_refresh})
    assert resp2.status_code == 200
    newest_refresh = resp2.json()["data"]["refresh_token"]

    # Step 3: Replay the first (revoked) token — should trigger family revocation
    replay_resp = client.post("/auth/refresh", json={"refresh_token": user_tokens["refresh_token"]})
    assert replay_resp.status_code == 401
    assert "revoked" in replay_resp.json()["message"].lower()

    # Step 4: The newest token should ALSO be revoked now (same family)
    resp3 = client.post("/auth/refresh", json={"refresh_token": newest_refresh})
    assert resp3.status_code == 401


def test_invalid_refresh_token(client):
    resp = client.post("/auth/refresh", json={"refresh_token": "not.a.valid.jwt"})
    assert resp.status_code == 401


def test_access_token_required_for_protected_routes(client):
    resp = client.get("/users/me")
    # HTTPBearer with auto_error=True returns 401 when no Authorization header
    assert resp.status_code in (401, 403)


def test_access_token_works_for_protected_routes(client, auth_headers):
    resp = client.get("/users/me", headers=auth_headers)
    assert resp.status_code == 200
