"""tests/test_change_password.py — Change password endpoint tests."""


def test_change_password_success(client, auth_headers, verified_user):
    resp = client.post(
        "/auth/change-password",
        json={"current_password": "Password1", "new_password": "NewPassword2"},
        headers=auth_headers,
    )
    assert resp.status_code == 200

    # Old password should no longer work
    old_login = client.post("/auth/login", json=verified_user)
    assert old_login.status_code == 401

    # New password should work
    new_login = client.post(
        "/auth/login",
        json={"email": verified_user["email"], "password": "NewPassword2"},
    )
    assert new_login.status_code == 200


def test_change_password_wrong_current(client, auth_headers):
    resp = client.post(
        "/auth/change-password",
        json={"current_password": "WrongPass1", "new_password": "NewPassword2"},
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "incorrect" in resp.json()["message"].lower()


def test_change_password_same_as_current(client, auth_headers):
    resp = client.post(
        "/auth/change-password",
        json={"current_password": "Password1", "new_password": "Password1"},
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "different" in resp.json()["message"].lower()


def test_change_password_requires_auth(client):
    resp = client.post(
        "/auth/change-password",
        json={"current_password": "Password1", "new_password": "NewPassword2"},
    )
    # HTTPBearer with auto_error=True returns 401 when no Authorization header
    assert resp.status_code in (401, 403)


def test_change_password_weak_new_password(client, auth_headers):
    resp = client.post(
        "/auth/change-password",
        json={"current_password": "Password1", "new_password": "weak"},
        headers=auth_headers,
    )
    assert resp.status_code == 422
