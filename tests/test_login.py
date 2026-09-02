"""tests/test_login.py — Login endpoint tests."""


def test_login_success(client, verified_user):
    resp = client.post("/auth/login", json=verified_user)
    assert resp.status_code == 200
    data = resp.json().get("data") or resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 15 * 60


def test_login_wrong_password(client, verified_user):
    resp = client.post("/auth/login", json={"email": verified_user["email"], "password": "WrongPass1"})
    assert resp.status_code == 401


def test_login_unknown_email(client):
    resp = client.post("/auth/login", json={"email": "nobody@example.com", "password": "Password1"})
    assert resp.status_code == 401


def test_login_unverified_user(client, registered_user):
    """Unverified users CAN log in (email verification is not a login gate by default)."""
    resp = client.post("/auth/login", json=registered_user)
    assert resp.status_code == 200


def test_login_account_lockout(client, verified_user, db):
    """After MAX_LOGIN_ATTEMPTS failures, account is locked."""
    for _ in range(5):
        client.post("/auth/login", json={"email": verified_user["email"], "password": "WrongPass1"})

    resp = client.post("/auth/login", json=verified_user)
    assert resp.status_code == 423  # HTTP 423 Locked
    assert "locked" in resp.json()["message"].lower()


def test_lockout_resets_on_success(client, verified_user, db):
    """Successful login after lock period resets the counter."""
    from app.models.user import User
    from datetime import datetime, timedelta, timezone

    user = db.query(User).filter(User.email == verified_user["email"]).first()
    user.failed_login_attempts = 5
    user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)  # expired lock
    db.commit()

    resp = client.post("/auth/login", json=verified_user)
    assert resp.status_code == 200

    db.refresh(user)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
