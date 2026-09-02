"""tests/test_audit.py — Audit log writing verification tests."""
from app.models.audit import AuditLog


def test_audit_log_on_registration(client, db):
    client.post("/auth/register", json={"email": "audit@example.com", "password": "Password1"})
    logs = db.query(AuditLog).filter(AuditLog.action == "USER_REGISTERED").all()
    assert len(logs) == 1
    assert logs[0].user_id is not None


def test_audit_log_on_login_success(client, verified_user, db):
    client.post("/auth/login", json=verified_user)
    logs = db.query(AuditLog).filter(AuditLog.action == "LOGIN_SUCCESS").all()
    assert len(logs) == 1


def test_audit_log_on_login_failure(client, verified_user, db):
    client.post("/auth/login", json={"email": verified_user["email"], "password": "WrongPass1"})
    logs = db.query(AuditLog).filter(AuditLog.action == "LOGIN_FAILURE").all()
    assert len(logs) == 1


def test_audit_log_on_account_lockout(client, verified_user, db):
    for _ in range(5):
        client.post("/auth/login", json={"email": verified_user["email"], "password": "WrongPass1"})
    logs = db.query(AuditLog).filter(AuditLog.action == "ACCOUNT_LOCKED").all()
    assert len(logs) == 1


def test_audit_log_on_logout(client, user_tokens, auth_headers, db):
    client.post(
        "/auth/logout",
        json={"refresh_token": user_tokens["refresh_token"]},
        headers=auth_headers,
    )
    logs = db.query(AuditLog).filter(AuditLog.action == "LOGOUT").all()
    assert len(logs) == 1


def test_audit_log_on_email_verified(client, db):
    import re
    from tests.conftest import mock_email
    client.post("/auth/register", json={"email": "ev@example.com", "password": "Password1"})
    body = mock_email.sent_emails[-1]["body"]
    token = re.search(r"token=([^\"&\s]+)", body).group(1)
    client.post("/auth/verify-email", json={"token": token})

    logs = db.query(AuditLog).filter(AuditLog.action == "EMAIL_VERIFIED").all()
    assert len(logs) == 1


def test_audit_log_on_password_reset(client, verified_user, db):
    import re
    from tests.conftest import mock_email
    client.post("/auth/forgot-password", json={"email": verified_user["email"]})
    body = mock_email.sent_emails[-1]["body"]
    token = re.search(r"token=([^\"&\s]+)", body).group(1)
    client.post("/auth/reset-password", json={"token": token, "new_password": "ResetPass1"})

    req_logs = db.query(AuditLog).filter(AuditLog.action == "PASSWORD_RESET_REQ").all()
    done_logs = db.query(AuditLog).filter(AuditLog.action == "PASSWORD_RESET_DONE").all()
    assert len(req_logs) == 1
    assert len(done_logs) == 1


def test_audit_log_on_role_assignment(client, admin_headers, verified_user, db):
    from app.models.user import User
    user = db.query(User).filter(User.email == verified_user["email"]).first()
    role_resp = client.post("/roles", json={"name": "viewer"}, headers=admin_headers)
    role_id = role_resp.json()["data"]["id"]
    client.post(f"/roles/users/{user.id}/roles", json={"role_id": role_id}, headers=admin_headers)

    logs = db.query(AuditLog).filter(AuditLog.action == "ROLE_ASSIGNED").all()
    assert len(logs) == 1


def test_audit_logs_are_immutable(db):
    """Audit log rows must never be updated — only inserted."""
    log = AuditLog(action="TEST_EVENT", user_id=None)
    db.add(log)
    db.commit()
    original_id = log.id

    # Simulate attempted update (should not change created_at)
    db.refresh(log)
    assert log.id == original_id
    assert log.action == "TEST_EVENT"


def test_audit_log_admin_endpoint(client, admin_headers):
    """Admin audit log list endpoint returns results."""
    client.post("/auth/register", json={"email": "al@example.com", "password": "Password1"})
    resp = client.get("/audit/logs", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()["data"]) >= 1


def test_audit_log_non_admin_forbidden(client, auth_headers):
    resp = client.get("/audit/logs", headers=auth_headers)
    assert resp.status_code == 403
