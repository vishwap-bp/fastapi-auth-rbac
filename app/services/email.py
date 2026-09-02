"""
services/email.py — Abstract email backend with SMTP, Console, and Mock implementations.

Usage:
    from app.services.email import send_email

    send_email(to="user@example.com", subject="Hello", html_body="<p>Hello</p>")

Backends:
    SMTPEmailBackend   — Default. Sends via SMTP. Auto-selected when SMTP_USER is set.
    ConsoleEmailBackend — Prints email to stdout. Auto-selected when SMTP_USER is empty.
    MockEmailBackend   — Stores emails in memory. Used in tests.

To swap the backend (e.g. in tests):
    from app.services.email import set_email_backend, MockEmailBackend
    mock = MockEmailBackend()
    set_email_backend(mock)
"""

from __future__ import annotations

import smtplib
from abc import ABC, abstractmethod
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import settings


class EmailBackend(ABC):
    """Abstract base — all backends implement send()."""

    @abstractmethod
    def send(self, to: str, subject: str, html_body: str) -> None:  # pragma: no cover
        raise NotImplementedError


class SMTPEmailBackend(EmailBackend):
    """Sends emails via SMTP with STARTTLS. Configured via .env SMTP_* variables."""

    def send(self, to: str, subject: str, html_body: str) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = to
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.EMAIL_FROM, to, msg.as_string())


class ConsoleEmailBackend(EmailBackend):
    """Prints emails to stdout. Used for local development when no SMTP is configured."""

    def send(self, to: str, subject: str, html_body: str) -> None:
        border = "=" * 60
        print(f"\n{border}\n📧 EMAIL (console backend)\nTo: {to}\nSubject: {subject}\n{border}\n{html_body}\n{border}\n")


class MockEmailBackend(EmailBackend):
    """Stores sent emails in memory. Used in tests to assert email was sent."""

    def __init__(self) -> None:
        self.sent_emails: list[dict] = []

    def send(self, to: str, subject: str, html_body: str) -> None:
        self.sent_emails.append({"to": to, "subject": subject, "body": html_body})

    def clear(self) -> None:
        self.sent_emails.clear()

    def last_email(self) -> dict | None:
        return self.sent_emails[-1] if self.sent_emails else None


def _build_default_backend() -> EmailBackend:
    """Select backend based on config: SMTP when credentials are set, Console otherwise."""
    if settings.SMTP_USER:
        return SMTPEmailBackend()
    return ConsoleEmailBackend()


# Module-level backend instance
_backend: EmailBackend = _build_default_backend()


def get_email_backend() -> EmailBackend:
    return _backend


def set_email_backend(backend: EmailBackend) -> None:
    """Replace the active backend. Called in tests to inject MockEmailBackend."""
    global _backend
    _backend = backend


from fastapi import HTTPException, status

def send_email(to: str, subject: str, html_body: str) -> None:
    """Send an email using the currently active backend."""
    try:
        _backend.send(to=to, subject=subject, html_body=html_body)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action succeeded, but failed to send email: {e}"
        )
