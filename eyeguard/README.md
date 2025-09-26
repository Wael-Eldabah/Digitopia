Software-only simulation / demo — no real systems will be contacted or modified.
# EyeGuard Simulation Platform

EyeGuard is a full-stack, software-only SOC training environment. It emulates network monitoring, threat intelligence lookups, alert triage, and incident reporting without touching production infrastructure.

## Architecture
- **Frontend:** React + Vite + TailwindCSS, React Query for data fetching, Cytoscape.js network map.
- **Backend:** FastAPI (async), httpx, Redis cache, PostgreSQL persistence via SQLAlchemy excerpts.
- **Database:** PostgreSQL schema in `db/schema.sql`.
- **Cache:** Redis (memory fallback available).
- **Mocks:** `/mocks/DataExamples.txt` plus JSON fixtures for threat intelligence fallbacks.

## Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL 14+
- Redis 6+ (optional; in-memory cache auto-fallback)

## Environment Variables
```
VT_API_KEY=<optional virustotal key>
OTX_API_KEY=<optional otx key>
ABUSE_API_KEY=<optional abuseipdb key>
DATABASE_URL=postgresql+asyncpg://eyeguard:eyeguard@localhost:5432/eyeguard
REDIS_URL=redis://localhost:6379/0
```
When keys are unset, the backend transparently loads responses from `/mocks/DataExamples.txt`.

## Backend Setup
```bash
cd eyeguard/backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # generate via pip-compile or freeze after development
uvicorn backend.app:app --reload
```
Apply schema to Postgres (optional for simulation mode):
```bash
psql -U eyeguard -d eyeguard -f ../db/schema.sql
```

## Frontend Setup
```bash
cd eyeguard/frontend
npm install
npm run dev
```
The Vite dev server proxies API traffic to `http://localhost:8000`.

## Running Tests
- **Backend unit/integration:** `pytest tests/backend`
- **Frontend unit tests:** `npm test`
- **E2E (Cypress):** `npm run cypress`

## Mock Data Workflow
- Update `/mocks/DataExamples.txt` JSON lines to adjust fallback verdicts.
- Additional reference payloads live in `/mocks/*.json` for demos and testing.

## Key Features
- Dashboard with Cytoscape network graph + device summary.
- Alerts table + modal for triage and status updates.
- Threat intelligence aggregation with caching and rate limiting.
- Reports export (CSV/PDF) using simulated data.
- Simulation terminal with whitelisted commands and rule-based alert triggers.
- Role-based settings module for signup approvals.

## Project Structure
```
eyeguard/
  backend/
    api_clients/
    models/
    routes/
    utils/
    app.py
  frontend/
    src/components/
    src/pages/
    App.jsx
  db/schema.sql
  mocks/
  tests/
    backend/
    frontend/
    e2e/
  FunctionalSpecification.md
  ERD.md
  OpenAPI.yaml
```

## Development Notes
- Stick to software-only constraints; no live network scans.
- Update Tailwind config / theme in `frontend/tailwind.config.js` as needed.
- Redis is optional; cache provider will fall back to in-memory store.
- Use `pytest -k search` to focus on reputation aggregation regressions.
- When extending mock data, keep provider-specific JSON lines within `DataExamples.txt` for auto-discovery.

## Troubleshooting
- **Invalid IP errors:** ensure inputs pass IPv4/IPv6 validation handled in backend.
- **Cache not available:** backend logs degrade gracefully; results still generated via fallback.
- **PDF export issues:** confirm `reportlab` is installed in the virtual environment.
