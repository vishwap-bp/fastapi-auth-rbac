"""
config.py — All application settings loaded from environment variables.

Every setting has a safe default for local development.
Production deployments must set SECRET_KEY and DATABASE_URL at minimum.
"""

from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore unknown env vars — safe for shared .env files
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    DATABASE_URL: str = "sqlite:///./auth.db"

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------
    SECRET_KEY: str = "CHANGE_THIS_IN_PRODUCTION"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ------------------------------------------------------------------
    # Security / Account lockout
    # ------------------------------------------------------------------
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # ------------------------------------------------------------------
    # CORS
    # Stored as a comma-separated string; use allowed_origins_list property.
    # ------------------------------------------------------------------
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    # ------------------------------------------------------------------
    # Frontend URL (used in email links for reset/verify)
    # ------------------------------------------------------------------
    FRONTEND_URL: str = "http://localhost:3000"

    # ------------------------------------------------------------------
    # Email (SMTP)
    # If SMTP_USER is empty the ConsoleEmailBackend is used automatically.
    # ------------------------------------------------------------------
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "no-reply@example.com"

    # ------------------------------------------------------------------
    # Google OAuth (optional)
    # Leave empty to disable the /auth/oauth/google endpoint.
    # ------------------------------------------------------------------
    GOOGLE_CLIENT_ID: Optional[str] = None

    @property
    def google_oauth_enabled(self) -> bool:
        return bool(self.GOOGLE_CLIENT_ID)


# Single shared settings instance imported everywhere
settings = Settings()
