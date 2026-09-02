"""
tests/conftest.py — Shared fixtures for the entire test suite.

Test database: SQLite (in-memory/file) — no PostgreSQL needed for tests.
Email backend: MockEmailBackend — no SMTP needed for tests.
Rate limiting: Disabled in tests (no per-IP limits).
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Force test settings BEFORE importing app modules
os.environ.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-production")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_auth.db")
os.environ.setdefault("FRONTEND_URL", "http://localhost:3000")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "15")
os.environ.setdefault("REFRESH_TOKEN_EXPIRE_DAYS", "7")
os.environ.setdefault("MAX_LOGIN_ATTEMPTS", "5")
os.environ.setdefault("LOCKOUT_DURATION_MINUTES", "15")

from app.database import Base, get_db
from app.services.email import MockEmailBackend, set_email_backend

# ------------------------------------------------------------------
# Import ALL models explicitly so every table is registered in
# Base.metadata BEFORE create_all() is called.
# ------------------------------------------------------------------
import app.models  # noqa: F401 — registers User, Role, Permission, RefreshToken, AuditLog

# ------------------------------------------------------------------
# Test database (SQLite file)
# ------------------------------------------------------------------
TEST_DB_URL = "sqlite:///./test_auth.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Create schema once at startup
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------------------------------------------
# Mock email backend — captures sent emails in memory
# ------------------------------------------------------------------
mock_email = MockEmailBackend()
set_email_backend(mock_email)


# ------------------------------------------------------------------
# FastAPI test app (mirrors example/main.py but with test overrides)
# ------------------------------------------------------------------
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, audit, roles, users

# Disable rate limiting during tests so it doesn't cause spurious 429s
auth.limiter.enabled = False

from app.utils.response import error_response
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from fastapi import status

test_app = FastAPI()

@test_app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return error_response(message=str(exc.detail), status_code=exc.status_code)

@test_app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    errors = exc.errors()
    error_data = [{"loc": err.get("loc"), "msg": err.get("msg")} for err in errors]
    message = "Validation Error"
    if errors:
        message = f"{errors[0].get('loc')[-1]}: {errors[0].get('msg')}"
    return error_response(message=message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, data=error_data)
test_app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
test_app.include_router(auth.router, prefix="/auth", tags=["Auth"])
test_app.include_router(users.router, prefix="/users", tags=["Users"])
test_app.include_router(roles.router, prefix="/roles", tags=["Roles"])
test_app.include_router(audit.router, prefix="/audit", tags=["Audit"])
test_app.dependency_overrides[get_db] = override_get_db


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def client():
    """HTTP test client — one per test so rate limiter state resets."""
    with TestClient(test_app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(autouse=True)
def clear_db_and_emails():
    """
    Drop and recreate all tables before each test for full isolation.
    Also resets slowapi's in-memory rate-limit counters so 429s from
    one test don't bleed into the next (same global MemoryStorage instance).
    """
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    mock_email.clear()
    # Reset slowapi rate-limit counters between tests
    try:
        from app.routers.auth import limiter as _rate_limiter
        _rate_limiter._storage.reset()
    except Exception:
        pass
    yield


@pytest.fixture
def db():
    """Provide a direct DB session for test assertions."""
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


# ------------------------------------------------------------------
# Helper fixtures — pre-created users and tokens
# ------------------------------------------------------------------

@pytest.fixture
def registered_user(client):
    """A registered but unverified user."""
    resp = client.post("/auth/register", json={
        "email": "user@example.com",
        "password": "Password1",
    })
    assert resp.status_code == 201
    return {"email": "user@example.com", "password": "Password1"}


@pytest.fixture
def verified_user(client, registered_user):
    """A registered and email-verified user."""
    # Get the verification token from the mock email
    email_body = mock_email.sent_emails[-1]["body"]
    import re
    match = re.search(r"token=([^\"&\s]+)", email_body)
    assert match, "Verification token not found in email"
    token = match.group(1)
    resp = client.post("/auth/verify-email", json={"token": token})
    assert resp.status_code == 200
    return registered_user


@pytest.fixture
def user_tokens(client, verified_user):
    """Access + refresh tokens for a verified regular user."""
    resp = client.post("/auth/login", json=verified_user)
    assert resp.status_code == 200
    return resp.json()["data"]


@pytest.fixture
def auth_headers(user_tokens):
    """Authorization headers for a regular user."""
    return {"Authorization": f"Bearer {user_tokens['access_token']}"}


@pytest.fixture
def admin_user(client, db):
    """A superuser for admin endpoint tests."""
    from app.models.user import User
    from app.services.password import hash_password

    admin = User(
        email="admin@example.com",
        hashed_password=hash_password("AdminPass1"),
        is_active=True,
        is_verified=True,
        is_superuser=True,
    )
    db.add(admin)
    db.commit()
    return {"email": "admin@example.com", "password": "AdminPass1"}


@pytest.fixture
def admin_tokens(client, admin_user):
    """Access + refresh tokens for the admin user."""
    resp = client.post("/auth/login", json=admin_user)
    assert resp.status_code == 200
    return resp.json()["data"]


@pytest.fixture
def admin_headers(admin_tokens):
    """Authorization headers for the admin user."""
    return {"Authorization": f"Bearer {admin_tokens['access_token']}"}
