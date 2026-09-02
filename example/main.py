"""
example/main.py — Demonstrates how to mount fastapi-auth-rbac in any FastAPI project.

This file is the entrypoint for the Docker container and local development.
A new project can copy this file and add their own routes below the auth routers.

Usage:
    uvicorn example.main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.database import Base, engine
from app.routers import auth, audit, roles, users

# ------------------------------------------------------------------
# Database setup
# For production: use `alembic upgrade head` instead of create_all.
# create_all is safe for local dev / tests.
# ------------------------------------------------------------------
Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------------
# Rate limiter — shared across all routers
# ------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

# ------------------------------------------------------------------
# FastAPI application
# ------------------------------------------------------------------
app = FastAPI(
    title="fastapi-auth-rbac",
    description=(
        "Production-ready drop-in Authentication & RBAC package for FastAPI. "
        "Mount this app or include the routers directly in your own FastAPI project."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi import status
from app.utils.response import error_response

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return error_response(message=str(exc.detail), status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    errors = exc.errors()
    error_data = [{"loc": err.get("loc"), "msg": err.get("msg")} for err in errors]
    message = "Validation Error"
    if errors:
        message = f"{errors[0].get('loc')[-1]}: {errors[0].get('msg')}"
    return error_response(message=message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, data=error_data)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc: RateLimitExceeded):
    return error_response(message="Rate limit exceeded", status_code=status.HTTP_429_TOO_MANY_REQUESTS)

# ------------------------------------------------------------------
# CORS — explicit allowed origins only, never "*" in production
# ------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ------------------------------------------------------------------
# Mount auth & RBAC routers — all paths prefixed here
# ------------------------------------------------------------------
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/users", tags=["Users"])
app.include_router(roles.router, prefix="/roles", tags=["Roles & Permissions"])
app.include_router(audit.router, prefix="/audit", tags=["Audit Logs"])


# ------------------------------------------------------------------
# Health check
# ------------------------------------------------------------------
@app.get("/health", tags=["Health"])
def health():
    """Simple health check endpoint."""
    return {"status": "ok", "service": "fastapi-auth-rbac"}


# ------------------------------------------------------------------
# Your project's routes go below this line
# Example:
#
# from fastapi import Depends
# from app.deps import require_permission
#
# @app.get("/reports", dependencies=[Depends(require_permission("reports:read"))])
# def get_reports():
#     return {"data": []}
# ------------------------------------------------------------------
