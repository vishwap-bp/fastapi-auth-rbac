"""tests/test_oauth.py — Google OAuth endpoint tests (mocked)."""
import importlib
from unittest.mock import MagicMock, patch

# Ensure oauth module is imported into sys.modules so patch can find it
import app.services.oauth  # noqa: F401

GOOGLE_USER_INFO = {
    "sub": "google-user-123",
    "email": "google@example.com",
    "email_verified": True,
}


def _mock_google_verify(token, *args, **kwargs):
    return GOOGLE_USER_INFO


def test_google_oauth_disabled_when_no_client_id(client, monkeypatch):
    """When GOOGLE_CLIENT_ID is not set, /auth/oauth/google returns 503."""
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "GOOGLE_CLIENT_ID", None)
    resp = client.post("/auth/oauth/google", json={"id_token": "any-token"})
    assert resp.status_code == 503
    assert "not configured" in resp.json()["message"].lower()


def test_google_oauth_creates_new_user(client, db, monkeypatch):
    import app.config as cfg
    import app.services.oauth as oauth_svc
    monkeypatch.setattr(cfg.settings, "GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(oauth_svc.id_token, "verify_oauth2_token", _mock_google_verify)

    resp = client.post("/auth/oauth/google", json={"id_token": "valid-google-token"})
    assert resp.status_code == 200
    data = resp.json().get("data") or resp.json()
    assert "access_token" in data
    assert "refresh_token" in data

    from app.models.user import User
    user = db.query(User).filter(User.email == "google@example.com").first()
    assert user is not None
    assert user.google_id == "google-user-123"
    assert user.oauth_provider == "google"
    assert user.is_verified is True
    assert user.hashed_password is None


def test_google_oauth_existing_user_linked(client, db, monkeypatch):
    """Google OAuth links to existing account with same email."""
    import app.config as cfg
    import app.services.oauth as oauth_svc
    monkeypatch.setattr(cfg.settings, "GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(oauth_svc.id_token, "verify_oauth2_token", _mock_google_verify)

    # Register normally first
    client.post("/auth/register", json={"email": "google@example.com", "password": "Password1"})

    # Now sign in via Google
    resp = client.post("/auth/oauth/google", json={"id_token": "valid-google-token"})
    assert resp.status_code == 200

    from app.models.user import User
    user = db.query(User).filter(User.email == "google@example.com").first()
    assert user.google_id == "google-user-123"
    assert user.hashed_password is not None  # Original password preserved


def test_google_oauth_invalid_token(client, monkeypatch):
    import app.config as cfg
    import app.services.oauth as oauth_svc
    monkeypatch.setattr(cfg.settings, "GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(
        oauth_svc.id_token, "verify_oauth2_token",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad token"))
    )

    resp = client.post("/auth/oauth/google", json={"id_token": "bad-token"})
    assert resp.status_code == 401
