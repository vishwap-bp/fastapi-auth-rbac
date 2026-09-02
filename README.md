# fastapi-auth-rbac

**A drop-in, production-ready Authentication & RBAC package for FastAPI.**
JWT auth, rotating refresh tokens, RBAC, session management, and a standardized response envelope — installable via `pip`, plug into any FastAPI project in minutes.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-async-009688)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Why this exists

Every new FastAPI project reimplements the same thing: register, login, JWT, roles, "who's logged in on which device," and an audit trail. This package packages that once — as an installable Python package, not source you copy-paste — so a new project adds one dependency and gets a complete, secure auth system.

## What's inside

| Area | What you get |
|:--|:--|
| 🔐 **Auth** | Register, login, logout, JWT access + rotating refresh tokens |
| 🔁 **Session management** | List active sessions, revoke one, revoke all others (IP + device tracked) |
| 🛡️ **RBAC** | Roles & permissions, admin-only management API, dependency-based route protection |
| 📧 **Account lifecycle** | Email verification, forgot/reset password, change password |
| 🌐 **Google Sign-In** | Optional, env-gated — no code changes to enable |
| 📋 **Audit log** | Immutable trail of every security-relevant event |
| 🚦 **Abuse protection** | Rate limiting + account lockout out of the box |
| 📦 **Standardized responses** | Every endpoint — success or error — returns the same predictable envelope |

## Standardized response envelope

Every endpoint returns the same shape, success or failure, so client-side handling never has to branch on endpoint:

```json
{
  "status": true,
  "statusCode": 200,
  "message": "Login successful.",
  "data": {
    "access_token": "...",
    "refresh_token": "..."
  }
}
```

Errors follow the identical shape with `"status": false` and the relevant `statusCode`.

---

## Quick start

```bash
pip install fastapi-auth-rbac

cp .env.example .env   # fill in your values
alembic upgrade head   # run migrations
```

```python
# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers import auth, users, roles, audit

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(users.router, prefix="/users", tags=["Users"])
app.include_router(roles.router, prefix="/roles", tags=["Roles"])
app.include_router(audit.router, prefix="/audit", tags=["Audit"])
```

Interactive docs at **`/docs`** — every route, request/response shape, ready to try.

---

## Endpoint reference (22 total)

### Authentication — `/auth`
| Method | Path | Description |
|:--|:--|:--|
| POST | `/auth/register` | Create account, triggers verification email |
| POST | `/auth/login` | Authenticate, tracks failed attempts, returns tokens |
| POST | `/auth/logout` | Blacklists the current refresh token |
| POST | `/auth/refresh` | Exchanges a valid refresh token for a new access token |
| GET | `/auth/verify-email` | Confirms email via magic-link token |
| POST | `/auth/forgot-password` | Generates and emails a reset token |
| POST | `/auth/reset-password` | Consumes a reset token, sets new password |
| POST | `/auth/change-password` | Authenticated password change |
| GET | `/auth/sessions` | List active sessions/devices |
| DELETE | `/auth/sessions/{session_id}` | Revoke one device session |
| POST | `/auth/oauth/google` | Google SSO login *(optional)* |

### Users — `/users`
| Method | Path | Description |
|:--|:--|:--|
| GET | `/users/me` | Your own profile + active roles |
| GET | `/users` | List all users *(admin)* |
| GET | `/users/{id}` | Get a specific user |
| POST | `/users/{id}/roles` | Assign a role to a user |
| DELETE | `/users/{id}/roles/{role_id}` | Remove a role from a user |

### Roles & Permissions — `/roles`, `/permissions`
| Method | Path | Description |
|:--|:--|:--|
| GET | `/roles` | List all roles |
| POST | `/roles` | Create a role |
| GET | `/roles/{id}` | Get a role + its permissions |
| POST | `/roles/{id}/permissions` | Attach a permission to a role |
| DELETE | `/roles/{id}/permissions/{perm_id}` | Remove a permission from a role |

### Audit — `/audit`
| Method | Path | Description |
|:--|:--|:--|
| GET | `/audit/logs` | Paginated, filterable audit trail *(admin)* |

---

## Protecting your own routes

```python
from fastapi import Depends
from app.deps import require_role, require_permission, get_current_active_user

@app.get("/admin-only", dependencies=[Depends(require_role("admin"))])
def admin_page():
    return {"message": "Welcome, admin"}

@app.get("/reports", dependencies=[Depends(require_permission("reports:read"))])
def reports():
    return {"data": []}

@app.get("/dashboard")
def dashboard(user = Depends(get_current_active_user)):
    return {"user": user.email}
```

---

## Tech stack

| Layer | Choice |
|:--|:--|
| Framework | FastAPI + Uvicorn (ASGI) |
| ORM | SQLAlchemy (async) |
| Migrations | Alembic |
| JWT | `python-jose` |
| Password hashing | `passlib` (bcrypt) |
| API docs | Built-in Swagger UI |
| Database | PostgreSQL (prod) / SQLite (dev, tests) |
| Tests | `pytest` + `httpx` |

## Environment variables

| Variable | Required | Default | Description |
|:--|:--|:--|:--|
| `DATABASE_URL` | ✅ | — | PostgreSQL connection string |
| `SECRET_KEY` | ✅ | — | Long random string for JWT signing |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | – | `15` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | – | `7` | Refresh token lifetime |
| `MAX_LOGIN_ATTEMPTS` | – | `5` | Attempts before lockout |
| `LOCKOUT_DURATION_MINUTES` | – | `15` | Lockout duration |
| `ALLOWED_ORIGINS` | – | `localhost:3000` | Comma-separated CORS origins |
| `FRONTEND_URL` | – | `localhost:3000` | Used in email links |
| `SMTP_HOST` / `PORT` / `USER` / `PASSWORD` | – | — | Email sending |
| `EMAIL_FROM` | – | `no-reply@example.com` | Sender address |
| `GOOGLE_CLIENT_ID` | – | empty = disabled | Enables Google Sign-In |

---

## Extending the `User` model

The core `User` model has a fixed field set, kept intentionally minimal so upgrades never conflict with your changes:

1. Create a `UserProfile` model in your own app with a 1:1 FK to `users.id`.
2. Add your custom fields there (`first_name`, `avatar_url`, `phone`, ...).
3. Run your own Alembic migration for that table.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

Runs on SQLite with a mock email backend — no external services required.

## Roadmap

- 🍎 Apple Sign-In *(requires a paid Apple Developer account)*
- 📊 Audit log export (CSV/JSON)
- 🔐 Permission inheritance / resource-level ownership checks
- 🏢 Multi-tenant, organization-scoped roles

## License

MIT
