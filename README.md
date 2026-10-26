# Secure Login System V2

Production-ready Flask authentication and user-management system with Argon2id, mandatory privileged-role 2FA, role-based access control, audit logging, and PostgreSQL-only enforcement in production.

## Features

- **Authentication**: Registration, login, case-insensitive identifier matching, generic error messages.
- **Passwords**: Argon2id with a versioned application pepper, policy enforcement, automatic rehash on pepper/version upgrade.
- **Two-factor authentication**: TOTP with QR provisioning, replay prevention, single-use recovery codes (stored as HMAC hashes), lockouts, mandatory 2FA for MANAGER/ADMIN/ADMINISTRATOR.
- **Access control**: Server-enforced RBAC with ranks (INPUTER 10, MANAGER 40, ADMIN 60, ADMINISTRATOR 100). Higher-rank accounts cannot be managed by lower-rank users.
- **Sessions**: Idle timeout, auth version invalidation, session clearing on privilege changes, CSRF protection.
- **Administration**: User creation, activation/deactivation, role assignment, administrative password resets (temporary password, forced change), administrative 2FA resets, audit log, record moderation.
- **Security**: Security headers, HTTPS enforcement in production, trusted proxy handling, rate limiting, safe logging, secure error pages, fail-closed production validation.
- **Records & reporting**: Role-aware dashboards, INPUTER record management, MANAGER reports.
- **CLI**: One-time token-gated `flask create-admin`, `flask seed-rbac`, `flask config-check`.

## Requirements

- Python 3.12
- PostgreSQL (production). SQLite is only for local development/testing; production fails closed without PostgreSQL.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Edit .env with strong random secrets
.\.venv\Scripts\python.exe -m flask --app wsgi:app db upgrade
.\.venv\Scripts\python.exe -m flask --app wsgi:app create-admin --username Cisco
```

The bootstrap is interactive and requires a `BOOTSTRAP_TOKEN` of at least 24 random characters. It refuses to run if any administrator already exists. Enter a unique password at the hidden prompt; never place passwords in source files, shell history, tickets, or logs. The account is stored with Argon2id, forced to change the password at first login, and required to enrol in 2FA. Remove or rotate `BOOTSTRAP_TOKEN` after the first administrator is created.

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Deployment (Render)

`render.yaml` is included for manual blueprint deployment. Do not commit secrets. Set strong values for all secrets in the Render environment. In production:
- Use PostgreSQL via `DATABASE_URL` (normalised to `postgresql+psycopg://`).
- Set `SESSION_COOKIE_SECURE=true`, `FLASK_ENV=production`, `TRUSTED_PROXY_COUNT=1`.
- Configure rate limiting with a persistent store if needed (default uses `memory://`).
- Run migrations with `flask db upgrade` during release (or before first start).
- Bootstrap the first administrator with `flask --app wsgi:app create-admin --username Cisco`, enter a strong password at the hidden prompt, then remove or rotate `BOOTSTRAP_TOKEN`.

Gunicorn cannot run natively on Windows; use a Linux host (Render, WSL) for real Gunicorn execution.

## Security notes

- No password, TOTP secret, or recovery code is ever written to logs or source files.
- Recovery codes are hashed with HMAC (pepper) and shown only once.
- Privileged roles require 2FA before accessing privileged areas.
- Administrative actions are audited and require re-authentication for sensitive operations.
- Session protection and idle timeout are enforced server-side.
- `DELETE` operations are performed via SQLAlchemy `delete()` where used.
