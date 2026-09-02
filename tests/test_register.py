"""tests/test_register.py — User registration tests."""
from tests.conftest import mock_email


def test_register_success(client):
    resp = client.post("/auth/register", json={"email": "new@example.com", "password": "Password1"})
    assert resp.status_code == 201
    assert "Account created" in resp.json()["message"]
    # Verification email should be sent
    assert len(mock_email.sent_emails) == 1
    assert mock_email.sent_emails[0]["to"] == "new@example.com"
    assert "verify" in mock_email.sent_emails[0]["subject"].lower()


def test_register_duplicate_email(client):
    client.post("/auth/register", json={"email": "dup@example.com", "password": "Password1"})
    resp = client.post("/auth/register", json={"email": "dup@example.com", "password": "Password1"})
    assert resp.status_code == 409


def test_register_weak_password_no_uppercase(client):
    resp = client.post("/auth/register", json={"email": "a@example.com", "password": "password1"})
    assert resp.status_code == 422


def test_register_weak_password_no_digit(client):
    resp = client.post("/auth/register", json={"email": "a@example.com", "password": "Password"})
    assert resp.status_code == 422


def test_register_password_too_short(client):
    resp = client.post("/auth/register", json={"email": "a@example.com", "password": "P1a"})
    assert resp.status_code == 422


def test_register_invalid_email(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "Password1"})
    assert resp.status_code == 422
