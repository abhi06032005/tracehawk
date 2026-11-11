# TraceHawk — Local Browser Security Inspection Platform

TraceHawk is a local-first, developer-centric browser security inspection platform. It allows engineers to launch an instrumented, visible Chromium browser on their desktop, interact with their web application (such as OWASP Juice Shop or internal services), passively record network and browser activity, and analyze the session for potential vulnerabilities and configuration anomalies.

---

## Architecture Overview

TraceHawk is built with a strictly segregated, local-first architecture:

```
                      +---------------------------------------+
                      |           Visible Chromium            |
                      |   (Playwright Headed on Host OS)      |
                      +-------------------+-------------------+
                                          |
                                          | CDP / Playwright Events
                                          v
+------------------------+      +-------------------------+      +------------------------+
|   TraceHawk Dashboard  | <==> |     TraceHawk Server    | <==> |  PostgreSQL 17 DB      |
| Next.js App (Port 3001)| SSE  |  Express API (Port 4000)|  pg  | Docker (127.0.0.1:5433)|
+------------------------+      +------------+------------+      +------------------------+
                                             |
                                             v
                                +-------------------------+
                                | Passive Security Engine |
                                |  (Headers, Cookies,     |
                                |   Storage, CORS, etc.)  |
                                +-------------------------+
```

### Components
- **Dashboard (`apps/web`)**: Next.js 15 App Router, TypeScript, Tailwind CSS, TanStack Table, Recharts, Lucide icons. Runs on `http://localhost:3001`.
- **Backend API & Engine (`apps/server`)**: Node.js 24, Express, Playwright Chromium orchestration, Server-Sent Events (SSE), Zod request validation. Strictly bound to `127.0.0.1:4000`.
- **Database**: PostgreSQL 17 running via Docker Compose bound to `127.0.0.1:5433` with persistent volume `tracehawk_postgres_data`. Integrated using Prisma ORM 7 (`@prisma/adapter-pg` and `pg`).

---

## Quickstart & Setup (Windows PowerShell)

All commands are tested and verified for Windows PowerShell.

### 1. Prerequisites
- **Node.js**: v24+
- **Docker Desktop**: Running locally
- **Terminal**: PowerShell

### 2. Start PostgreSQL 17
```powershell
docker compose up -d
```
*PostgreSQL 17 will initialize on `127.0.0.1:5433`.*

### 3. Install Dependencies & Set Up Database
```powershell
npm install
npm run db:push
npx playwright install chromium
```

### 4. Start TraceHawk Stack
```powershell
npm run dev
```
- Dashboard: **http://localhost:3001**
- API Server: **http://127.0.0.1:4000**
- API Health: **http://127.0.0.1:4000/api/health**

---

## User Workflow & Walkthrough

1. **Open Dashboard**: Navigate to `http://localhost:3001`.
2. **Create Project**: Click **New Project** and enter target URL (e.g., `http://localhost:3000` for OWASP Juice Shop).
3. **Launch Browser & Record**: Click **Record** / **Launch Browser & Record**.
   - A visible Chromium desktop window launches on your host OS.
   - TraceHawk automatically navigates to your target application.
4. **Interact Manually**:
   - Navigate between views and dashboards.
   - Submit forms, log in, sign out, trigger API requests.
   - Open additional tabs.
5. **Watch Real-Time Telemetry**:
   - The TraceHawk dashboard streams live request counters, error alerts, active tab tracking, and recently captured endpoints via SSE.
6. **Stop Recording**: Return to the dashboard and click **Stop Recording** (or simply close the Chromium window).
   - TraceHawk automatically snapshots cookies, localStorage, sessionStorage, and IndexedDB metadata, redacting secrets.
   - Session data is persisted to PostgreSQL.
7. **Analyze Session**: Click **Analyze Session**.
   - The deterministic passive analysis engine evaluates the session and flags configuration vulnerabilities.
8. **Inspect Findings & Export**:
   - Inspect individual findings, review supporting requests, examine attacker impact, and read remediation guidance.
   - Export reports as JSON, sanitized traffic, or sanitized HAR.

---

## Passive Security Checks

TraceHawk implements real deterministic security auditing:

| Rule Category | Description | CWE |
|---|---|---|
| **Security Headers** | Missing Content-Security-Policy (CSP), HSTS, X-Content-Type-Options: nosniff, anti-clickjacking X-Frame-Options, Referrer-Policy | CWE-693, CWE-319, CWE-1021 |
| **Insecure Cookies** | Sensitive session cookies missing `HttpOnly`, `Secure`, or `SameSite` protections | CWE-614 |
| **Storage Disclosure** | Bearer tokens, JWTs, or credentials stored in HTML5 localStorage or sessionStorage (accessible via XSS) | CWE-922 |
| **URL Query Secrets** | Tokens, API keys, and passwords transmitted inside URL query parameters | CWE-598 |
| **Permissive CORS** | Wildcard `*` origins on API endpoints or credentials allowed with wildcard origins | CWE-942 |
| **Verbose Errors & Stacks** | HTTP 500 errors disclosing internal server paths, Sequelize, SQL, or Node.js stack traces | CWE-209 |
| **Version Disclosure** | `Server`, `X-Powered-By`, `X-AspNet-Version` disclosing exact server and framework versions | CWE-200 |
| **Mixed Content** | Insecure HTTP subresources loaded on HTTPS pages | CWE-311 |
| **Repeated Failures** | Excessive 5xx server errors on specific endpoints (potential stability / DoS anomaly) | CWE-754 |

---

## Privacy & Redaction Architecture

- **Authorization Headers**: Bearer tokens and Basic credentials are automatically masked (`Bearer [REDACTED_TOKEN]`).
- **Cookie Redaction**: Sensitive cookie values are redacted while preserving names and security attributes.
- **Payload Sanitization**: JSON request and response bodies are filtered for sensitive keys (`password`, `secret`, `token`, `creditCard`, `apiKey`).
- **Payload Limits**: Bodies exceeding 512 KB or binary media (images, audio, video) are skipped to prevent unbounded storage accumulation.
- **Local Binding**: Express server binds strictly to `127.0.0.1:4000` to prevent unauthorized cross-network access.

---

---

## DeepHat Autonomous Security Investigation (Phase 2)

Phase 2 uses a single evidence-driven agent and a configurable OpenAI-compatible chat-completions endpoint. There is no scripted fallback. Disabled/unreachable models or invalid responses fail explicitly without creating simulated findings.

See [PHASE2.md](PHASE2.md) for setup, permissions, evidence handling, tool limitations and dry-check commands. The original recorder and browser manager remain in place.

---
## Hosted vs. Local Companion Architecture

A cloud-hosted Next.js deployment cannot launch a visible GUI browser window on a user's local laptop due to operating system boundaries. In a production enterprise deployment:
1. The dashboard can run in the cloud.
2. The user runs a lightweight **TraceHawk Local Companion** agent on their workstation that handles the Playwright Chromium process and streams telemetry over a secure WebSocket back to the centralized dashboard.

For this local-first version, the Express backend and Playwright process run locally on the Windows host.

---

## Automated Tests

Run the test suite:
```powershell
npm run test
```
- **Unit Tests**: Redaction of headers, URLs, JSON bodies, storage items, and passive security check rules.
- **End-to-End Tests**: Complete flow executing project creation, visible Chromium launch, live navigation, storage snapshotting, session finalization, passive analysis, and report export.


## Start everything with one command

From `D:\tracehawk`, run `npm run dev`. The startup hook starts Docker Desktop if needed, starts PostgreSQL, the local Juice Shop demo and ZAP, generates the database client, and applies pending migrations before launching the API and dashboard. Docker Desktop and project dependencies must already be installed.

Open http://localhost:3001. The local demo target is http://localhost:3000. Press Ctrl+C in the terminal to stop both development servers. Containers retain their data and can be stopped with `docker compose --profile security-test stop`.
