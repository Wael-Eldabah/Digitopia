Software-only simulation / demo — no real systems will be contacted or modified.
# EyeGuard Functional Specification

## Overview
EyeGuard is a software-only simulation platform that emulates SOC workflows for monitoring network devices, evaluating IP reputation, and orchestrating responses. The system integrates simulated data sources, mocked threat intelligence feeds, and interactive tooling to train analysts without touching production infrastructure.

## Personas & Roles
- **SOC Analyst**: Monitors dashboards, triages alerts, runs simulations, and updates incident status.
- **Incident Responder**: Investigates escalated incidents, exports reports, and coordinates containment actions.
- **Manager**: Oversees user management, approves sign-ups, audits reports, and configures policies.

## Functional Requirements
1. **Authentication & Authorization**
   - Enforce role-based access control (RBAC) across SOC Analyst, Incident Responder, and Manager roles.
   - Restrict sign-up to emails ending with `@eyeguard.com`.
   - Queue pending sign-ups for Manager approval before granting access.
   - Maintain session tokens (simulated) for frontend state management.

2. **Dashboard**
   - Display a real-time network map using Cytoscape.js with simulated device nodes and traffic edges.
   - Provide device inventory table with sortable columns (IP, destination, traffic volume, country, status).
   - Highlight devices flagged with open alerts.

3. **Alerts & Incidents**
   - Render a paginated, filterable alert list (date, type, severity, status, source/destination IP).
   - Support viewing detailed alert context (indicator breakdown, correlation, recommended action).
   - Allow status transitions: Open → Acknowledged → Resolved.
   - Track automatic versus manual resolution actions.

4. **Reports**
   - Maintain report entries linked to alerts with narrative summaries and remediation steps.
   - Support export to CSV (tabular alert data) and PDF (narrative report) on demand.
   - Provide report detail view containing linked alerts, timeline, and verdict summary.

5. **Simulation Module**
   - Let analysts add or remove simulated devices with IP, hostname, role, and traffic volume.
   - Provide a simulated terminal supporting commands `ls`, `cd`, `nano`/`edit`, `mv`, `rm`, `ip`.
   - Trigger alerts for:
     - Any file edit (record pre/post SHA256 hash in `file_snapshots`).
     - Navigating into `/private` directory.
     - Traffic volume exceeding 10GB within a session.
     - Negative reputation verdict (High severity) from threat intelligence checks.
   - Allow toggling device connectivity to represent automatic blocking actions.

6. **Threat Intelligence Integration**
   - Expose REST endpoint `GET /api/v1/search?ip=...` performing IP validation, cache lookup (Redis), and aggregated reputation fetch.
   - When API keys (`VT_API_KEY`, `OTX_API_KEY`, `ABUSE_API_KEY`) are present, query VirusTotal, OTX, and AbuseIPDB in parallel with retry/backoff and timeout guards.
   - On missing keys or failures, fallback to mock responses stored in `/mocks/DataExamples.txt` and `/mocks/*.json`.
   - Normalize responses via transformer functions (`transform_vt`, `transform_otx`, `transform_abuse`) and compute severity/action verdicts.
   - Persist aggregated result in PostgreSQL (`ip_reputation`, `api_responses_log`) and cache in Redis (TTL 1h).

7. **Settings & User Management**
   - Present Manager dashboard for pending user approvals with approve/reject controls.
   - Permit role reassignment and deactivation of existing users.
   - Expose audit trail for user onboarding activities.

8. **Resilience & Observability**
   - Implement structured logging across backend routes and API clients.
   - Surface backend health status (database, cache connectivity) to the frontend.
   - Handle network/API errors gracefully with descriptive messaging.

## Non-Functional Requirements
- Software-only demo; never touch real systems.
- Config-driven thresholds (traffic limits, retry counts) with sane defaults.
- FastAPI backend should maintain 95% unit test coverage for rules engine and transformers.
- React frontend should implement component-level Jest tests and Cypress e2e smoke tests.
- Provide Docker Compose for local simulation (future scope noted in README).

## UX Flows & Acceptance Criteria
### Dashboard Flow
1. Analyst logs in (simulated auth) and loads dashboard.
2. Network map animates edges representing traffic volume.
3. Devices table updates every 10 seconds from backend simulated feed.
4. Selecting node focuses related device row.
5. **Acceptance**: Device list matches backend payload; high-severity alerts highlight corresponding nodes.

### Alert Triage Flow
1. Analyst navigates to Alerts & Incidents tab.
2. Analyst filters by severity=High.
3. Selecting alert opens modal with detailed context and action buttons.
4. Analyst updates status to Resolved; backend records status change and timestamp.
5. **Acceptance**: Updated status appears immediately; audit log entry created.

### Report Export Flow
1. Responder opens Reports page and selects incident.
2. Responder clicks “Export CSV”; file download is triggered via backend endpoint.
3. Responder clicks “Export PDF”; receives simulated PDF (base64 or blob) with summary.
4. **Acceptance**: Export endpoints return valid files with consistent data.

### Simulation Flow
1. Analyst opens Simulation page and adds device with IP + traffic volume.
2. Backend validates IP, stores device in `simulation_sessions`, and updates network map.
3. Analyst opens terminal; runs `cd /private` causing alert trigger.
4. Backend logs file system action and creates alert with severity Medium.
5. Analyst resolves alert; device stays connected unless auto-block triggered.
6. **Acceptance**: Alerts fire on rule triggers, device block state toggles correctly, and session history persists.

### Settings Flow
1. Manager opens Settings page; sees pending signup requests.
2. Manager approves a request; backend updates user role and sends notification (simulated toast).
3. **Acceptance**: Pending queue decreases, user becomes active with assigned role.

## API Acceptance Criteria
- `GET /api/v1/search` returns HTTP 400 for invalid IP, 200 with normalized payload otherwise.
- All endpoints include structured error body `{ error_code, message, details? }` on failure.
- Rate limiting simulated via in-memory counter (per IP per minute) returning HTTP 429.
- All database writes occur within transactions with rollback on exception.

## Security Considerations
- Input validation on all API payloads (pydantic models).
- Escape/encode user-provided text in frontend to prevent XSS.
- Guard simulated terminal from arbitrary command execution (whitelist only).
- Store API keys only in environment variables; never log secrets.

## Logging & Observability
- Use `structlog` for JSON logs with correlation ID per request.
- Emit metrics counters (simulated) for alerts raised, API calls, cache hits/misses.
- Provide `/api/v1/health` summarizing DB and cache connectivity.

## Dependencies & Tooling
- Backend: FastAPI, httpx, redis-py, SQLAlchemy (async), structlog, reportlab (PDF), pandas (CSV export), python-dotenv, pytest, pytest-asyncio.
- Frontend: React 18, Vite, TailwindCSS, React Query, Axios, Zustand (state), Recharts, Jest, React Testing Library, Cypress.
- DevOps: Docker Compose definitions for Postgres + Redis (not executed in demo), pre-commit hooks (black, isort, eslint, prettier).

## Open Questions / Assumptions
- Authentication simulated with mocked JWT issued by backend for demo.
- PDF generation performed server-side and returned as base64 string for download.
- Live WebSocket updates simulated via polling; WebSocket support noted as future enhancement.

