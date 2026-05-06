# SecureWatch Postgres Setup

This document records the local Postgres wiring for SecureWatch.

## Runtime Requirement

SecureWatch requires Postgres at runtime. If neither `SECUREWATCH_DATABASE_URL` nor `DATABASE_URL` is set, the backend fails startup with:

```text
DATABASE_URL not set. SecureWatch requires Postgres. See docs/postgres_setup.md
```

SQLite is not a supported runtime fallback. This keeps incident persistence, entity risk, AI context, WebSocket broadcast state, and Pydantic response contracts on one consistent database schema.

## Current State

SecureWatch is configured to use local Postgres through `.env`:

```env
DATABASE_URL=postgresql+psycopg://securewatch:securewatch@localhost:5432/securewatch
```

Verified local Postgres details:

| Item | Value |
|---|---|
| Postgres install | `C:\Program Files\PostgreSQL\18\bin` |
| Windows service | `postgresql-x64-18` |
| Host | `localhost` |
| Port | `5432` |
| App database | `securewatch` |
| App role | `securewatch` |
| App password | `securewatch` |

## Tables

The app creates tables automatically on startup via SQLAlchemy metadata.

Verified tables:

```text
entity_risk
incident_audit
incidents
metrics
```

Verified row counts after migration/startup:

```text
incidents       29
incident_audit  17
metrics          1
entity_risk     61
```

## One-Time Setup

The helper script creates or updates the app role and creates the database if it does not already exist:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_postgres.ps1
```

The script can read the local Postgres admin password from `.env`:

```env
POSTGRES_ADMIN_PASSWORD=your_local_postgres_admin_password
```

After setup succeeds, remove `POSTGRES_ADMIN_PASSWORD` from `.env`. The backend does not need the admin password during normal operation.

## Normal App Startup

Start the API from the repo root:

```powershell
uvicorn app.main:app --reload --port 8000
```

On startup, the app:

1. Loads `.env`.
2. Reads `SECUREWATCH_DATABASE_URL` first, then `DATABASE_URL`.
3. Requires a Postgres URL and rejects SQLite or other database schemes.
4. Builds a SQLAlchemy engine with `psycopg`.
5. Runs `Base.metadata.create_all(...)`.
6. Loads persisted incidents, metrics, audit events, and entity risk from Postgres.

## Verification

Health check:

```powershell
python -c "from fastapi.testclient import TestClient; from app.main import app; response = TestClient(app).get('/health'); print(response.status_code, response.json())"
```

Expected:

```text
200 {'ok': True}
```

Confirm engine URL without printing the password:

```powershell
python -c "from app.db.database import engine; print(engine.url.render_as_string(hide_password=True))"
```

Expected:

```text
postgresql+psycopg://securewatch:***@localhost:5432/securewatch
```

List tables:

```powershell
$env:PGPASSWORD="securewatch"
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -h localhost -p 5432 -U securewatch -d securewatch -tAc "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"
$env:PGPASSWORD=$null
```

## Docker Compose

Docker Compose is also wired for Postgres. Inside Compose, the host is the service name `postgres`, not `localhost`:

```env
DATABASE_URL=postgresql+psycopg://securewatch:securewatch@postgres:5432/securewatch
```

Run:

```powershell
docker compose up --build
```

Compose starts:

| Service | Purpose |
|---|---|
| `postgres` | Postgres database container |
| `securewatch` | FastAPI backend |

## Notes

- `psycopg[binary]>=3.1` is required and is listed in `requirements.txt`.
- The app accepts both `postgres://...` and `postgresql://...`; they are normalized to `postgresql+psycopg://...`.
- `SECUREWATCH_DATABASE_URL` takes precedence over `DATABASE_URL`.
- The legacy JSON incident and audit files are used for first-run migration when the incidents table is empty.
