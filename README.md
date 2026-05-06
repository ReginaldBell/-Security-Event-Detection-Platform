# SecureWatch Engine

![Dashboard Screenshot](dashboard/src/images/dashboard-pic.png)

## What It Is

SecureWatch is a security detection and AI validation platform built around two independent pipelines. The first ingests authentication logs, normalizes them through configurable field mappings, and applies sliding-window threat detection with full incident lifecycle management. The second runs synthetic adversarial prompts through a 4-layer AI defense stack — DLP, pattern controls, semantic classification, and output filtering — validating whether the controls hold against known attack categories using a live Claude API connection.

---

## Architecture

> *Figma architecture diagram coming soon.*

**Threat detection pipeline:** Raw events arrive at `POST /ingest/`, pass through YAML-driven field normalization and Pydantic v2 validation, then enter the detection engine where two sliding-window state machines (brute-force T1110 and password spray T1110.003) run over a 60-second deque. Incidents are deduplicated by deterministic SHA-256 ID, merged on new evidence, persisted to Postgres, and exposed through a REST API consumed by the React dashboard.

**AI security pipeline:** Synthetic attack prompts (prompt injection, jailbreak, data exfiltration, DLP secret leakage, and more) are passed through four sequential defense layers before reaching the LLM. Each layer independently votes on detection. In live mode the pipeline calls Claude Haiku via the Anthropic API and a semantic classifier judges the raw response for bypasses that pattern matching missed. Results feed into the incident registry as `ai_pipeline` source incidents.

## Test Suite

```bash
pytest tests/ -q   # 106 tests, ~2.4s
```

---

## Key Features

- **Sliding-window brute-force and password spray detection** — 60-second deque-based state machines with severity scaling and deterministic SHA-256 incident IDs
- **MITRE ATT&CK mapped incidents with full lifecycle** — open → acknowledged → escalated → closed transitions, SLA enforcement, audit trail, and auto-reopen on new evidence
- **AI security testing against a live Claude API** — 17 synthetic attack scenarios run against real model responses in live mode with retry and overload handling
- **4-layer AI defense validation** — DLP secret scanning, pattern input/output controls, live semantic classification, and output redaction run in sequence with per-layer attribution
- **Entity risk scoring with exponential decay** — weighted accumulation per incident type (brute-force +10, credential abuse +25, AI attacks +30–45) with a 24-hour half-life, rehydrated from Postgres on startup
- **Playbook-driven triage with SPL detection logic** — every incident carries analyst questions, pivot queries, escalation conditions, and a portable Splunk SPL detection query
- **Detection quality validation with MITRE coverage tracking** — 12-scenario suite with pass/fail scoring, latency measurement, and per-technique detection rate across all validation runs

---

## Setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- PostgreSQL 14+
- Anthropic API key (required for AI pipeline live mode only)
- Docker (optional, for containerized deployment)

### Postgres

```bash
psql -U postgres -c "CREATE USER securewatch WITH PASSWORD 'securewatch';"
psql -U postgres -c "CREATE DATABASE securewatch OWNER securewatch;"
```

### Environment Variables

Create a `.env` file in the project root:

```env
SECUREWATCH_DATABASE_URL=postgresql+psycopg://securewatch:securewatch@localhost:5432/securewatch
ANTHROPIC_API_KEY=sk-ant-...        # required for AI pipeline live mode only
```

`SECUREWATCH_DATABASE_URL` takes priority over `DATABASE_URL` if both are set. The URL must use the `postgresql+psycopg://` scheme.

Or set them in your shell before starting:

```powershell
# Windows PowerShell
$env:SECUREWATCH_DATABASE_URL="postgresql+psycopg://securewatch:securewatch@localhost:5432/securewatch"
$env:ANTHROPIC_API_KEY="sk-ant-..."
```

### Run

```bash
# Install dependencies
pip install -r requirements.txt

# Start the API (tables are created automatically on first boot)
uvicorn app.main:app --reload --port 8000
```

```bash
# Build and serve the dashboard (production)
cd dashboard
npm install
npm run build       # output served by FastAPI at /

# Or run the dev server separately
npm run dev         # hot reload at :5173
```

```bash
# Docker (starts API + Postgres together)
docker compose up -d
```

### Demo Seed

Load a set of pre-built incidents to explore the dashboard without ingesting live data:

```bash
curl -X POST http://localhost:8000/incidents/demo-seed
```

Or click **Demo Seed** in the dashboard toolbar.

To ingest a real brute-force scenario manually:

```bash
curl -X POST http://localhost:8000/ingest/ \
  -H "Content-Type: application/json" \
  -d '[
    {"timestamp":"2025-12-21T05:00:00Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","source":"demo"},
    {"timestamp":"2025-12-21T05:00:01Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","source":"demo"},
    {"timestamp":"2025-12-21T05:00:02Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","source":"demo"},
    {"timestamp":"2025-12-21T05:00:03Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","source":"demo"},
    {"timestamp":"2025-12-21T05:00:04Z","source_ip":"203.0.113.10","username":"alice","event_type":"login_attempt","result":"failure","source":"demo"}
  ]'
```

---

## API

Interactive API docs (Swagger UI) are available at:

```
http://localhost:8000/docs
```

The full OpenAPI spec is at `/openapi.json`. The schema is contract-locked in CI — any unintentional change to the spec fails the build. To regenerate after an intentional API change:

```bash
python scripts/export_openapi_snapshot.py
```

---

## Status

SecureWatch is an MVP security detection platform demonstrating event ingestion, normalization, detection, incident lifecycle management, and AI defense validation. It is not yet production SOC infrastructure; future hardening would include auth/RBAC, durable ingestion queues, observability, tenancy, and replayable detection pipelines.

## Roadmap

- **Multi-tenant support** — per-organization incident namespacing and role-based access control
- **LLM analyst integration** — surface AI-generated triage narratives in the incident panel (secure context layer is built; LLM call and UI rendering are next)
- **Expanded MITRE technique coverage** — lateral movement (T1021), persistence (T1053), and execution (T1059) detection rules
- **Streaming ingest** — Kafka/Kinesis adapter for high-volume real-time log pipelines
