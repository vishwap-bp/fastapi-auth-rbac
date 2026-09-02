"""tests/test_verify_email.py — Email verification flow tests."""
import re

from tests.conftest import mock_email


def _extract_verify_token(body: str) -> str:
    match = re.search(r"token=([^\"&\s]+)", body)
    assert match, f"Verify token not found in email body: {body}"
    return match.group(1)


def test_verify_email_success(client):
    client.post("/auth/register", json={"email": "verify@example.com", "password": "Password1"})
    token = _extract_verify_token(mock_email.sent_emails[-1]["body"])

    resp = client.post("/auth/verify-email", json={"token": token})
    assert resp.status_code == 200
    assert "verified" in resp.json()["message"].lower()


def test_verify_email_marks_user_verified(client, db):
    from app.models.user import User
    client.post("/auth/register", json={"email": "check@example.com", "password": "Password1"})
    token = _extract_verify_token(mock_email.sent_emails[-1]["body"])
    client.post("/auth/verify-email", json={"token": token})

    user = db.query(User).filter(User.email == "check@example.com").first()
    assert user.is_verified is True


def test_verify_email_invalid_token(client):
    resp = client.post("/auth/verify-email", json={"token": "invalid-token"})
    assert resp.status_code == 400


def test_verify_email_already_verified(client):
    client.post("/auth/register", json={"email": "dbl@example.com", "password": "Password1"})
    token = _extract_verify_token(mock_email.sent_emails[-1]["body"])
    client.post("/auth/verify-email", json={"token": token})

    # Second attempt
    resp = client.post("/auth/verify-email", json={"token": token})
    assert resp.status_code == 400
    assert "already" in resp.json()["message"].lower()
