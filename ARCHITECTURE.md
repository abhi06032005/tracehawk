# DeepHat / TraceHawk — Architecture Specification

## 1. System Overview

DeepHat / TraceHawk is a modular, autonomous AI security testing platform. It combines real browser telemetry (Playwright and Chrome extension), deterministic passive security analysis, external specialized open-source scanners (OWASP ZAP, Nuclei, Semgrep, Trivy, Gitleaks), a strict Security Policy Gateway, and the primary **DeepHat-V1-7B** reasoning model deployed via vLLM with 100,000-token YaRN context extension.

---

## 2. Target Architecture

```
+-----------------------------------------------------------------------------------+
|                                React Dashboard                                    |
|             (Next.js 15 App Router, React 19, Tailwind CSS, Port 3001)            |
+-----------------------------------------+-----------------------------------------+
                                          | HTTP / Server-Sent Events (SSE)
+-----------------------------------------v-----------------------------------------+
|                               Express Backend API                                 |
|                       (Node.js / TypeScript, Port 4000)                           |
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                               DeepHat Orchestrator                                |
|        (InvestigationManager: OBSERVE -> ANALYZE -> PLAN -> VERIFY -> EVALUATE)   |
+--------------------+--------------------+--------------------+--------------------+
                     |                    |                    |
+--------------------v----+     +---------v----------+     +---v--------------------+
| DeepHat-V1-7B (vLLM)    |     | Evidence Gate      |     | Ephemeral Credentials  |
| 100k YaRN Context       |     | (gateHypothesis    |     | In-memory vault        |
| OpenAI-compatible API   |     | Backend proofs)    |     | 30m TTL, Local reveal  |
+-------------------------+     +--------------------+     +------------------------+
                     |
+--------------------v--------------------------------------------------------------+
|                              Security Policy Gateway                              |
|       - Domain & Origin Allowlisting        - Request Budget & Concurrency        |
|       - Mode Enforcement (Passive/Active)   - Operator Approvals (Mutating)       |
|       - SSRF / Metadata Protection          - Emergency Stop & Execution Timeouts |
+-----------------------------------------+-----------------------------------------+
                                          | Policy-Governed Dispatch
+-----------------------------------------v-----------------------------------------+
|                             Centralized Tool Registry                             |
+-------------------+--------------------+--------------------+---------------------+
| Tool              | Risk Tier          | Scope              | Upstream / Engine   |
+-------------------+--------------------+--------------------+---------------------+
| Session Evidence  | READ_ONLY          | Local DB           | DeepHat Core        |
| HTTP Exchange     | READ_ONLY          | Local DB           | DeepHat Core        |
| Storage Snapshot  | READ_ONLY          | Local DB           | DeepHat Core        |
| Console & WS      | READ_ONLY          | Local DB           | DeepHat Core        |
| Security Headers  | PASSIVE            | Local DB / Exch    | DeepHat Core        |
| ZAP Passive Scan  | PASSIVE            | Docker / Import    | OWASP ZAP           |
| Crawler / Spider  | ACTIVE_SAFE        | Allowlisted Scope  | Playwright / ZAP    |
| Account Compare   | ACTIVE_SAFE        | Allowlisted Scope  | DeepHat Core (BOLA) |
| Rate-Limit Check  | ACTIVE_SAFE        | Allowlisted Scope  | DeepHat Core        |
| Mutating Probes   | MUTATING_APPROVAL  | Allowlisted Scope  | DeepHat Core        |
| Nuclei Scanner    | ACTIVE_SAFE        | Allowlisted Scope  | Nuclei CLI          |
| Semgrep SAST      | PASSIVE            | Authorized Dir     | Semgrep CLI         |
| Trivy SCA         | PASSIVE            | Authorized Dir     | Trivy CLI           |
| Gitleaks Secrets  | PASSIVE            | Authorized Dir     | Gitleaks CLI        |
+-------------------+--------------------+--------------------+---------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                        Unified Finding Normalization                              |
|   (Statuses: discovered | needs_verification | verified | false_positive | inconcl)|
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                            PostgreSQL 17 Database                                 |
|            (Docker :5433, Persistent Volume: tracehawk_postgres_data)             |
+-----------------------------------------------------------------------------------+
```

---

## 3. Specialized Security Agents

The platform decomposes security analysis across 6 specialized personas powered by **DeepHat-V1-7B**:

1. **Agent 1 — Reconnaissance & Attack Surface**:
   - Automated route discovery via Playwright Crawler.
   - Form and input parameter cataloging.
   - Technology fingerprinting and attack surface inventory.
2. **Agent 2 — Web Application Security**:
   - Evaluates OWASP Top 10 vulnerabilities (CORS, injection indicators, XSS indicators, session weaknesses).
   - Coordinates Nuclei web misconfiguration checks.
3. **Agent 3 — API Security**:
   - Analyzes REST/GraphQL endpoints against OWASP API Security Top 10.
   - BOLA / IDOR detection via multi-account comparison scenarios.
   - Rate limiting, excessive data exposure, and method fuzzing.
4. **Agent 4 — Source Code Security**:
   - Source-code-aware SAST (Semgrep).
   - Dependency vulnerability auditing (Trivy).
   - Repository secret detection (Gitleaks).
5. **Agent 5 — Verification & False Positive Reduction**:
   - Deterministic reproduction of potential vulnerabilities.
   - Evidence collection proving or refuting exploitability.
   - Moves findings between `needs_verification`, `verified`, and `false_positive`.
6. **Agent 6 — Reporting & Remediation**:
   - Deduplicates and normalizes findings.
   - Maps CWE, CVSS, and OWASP categories.
   - Generates actionable remediation guides and exports multi-format reports (JSON, Markdown, PDF).

---

## 4. Policy Gateway & Security Guardrails

The `SecurityPolicyGateway` ensures that no autonomous agent can execute unauthorized or destructive actions:

- **Target Allowlisting**: All URLs must strictly match the project's configured `allowedOrigins`. Wildcards are disallowed for active requests.
- **SSRF Prevention**: Requests to cloud metadata (`169.254.169.254`), link-local IPs, carrier-grade NAT, or internal hostnames are rejected immediately.
- **Risk Tiers**:
  - `READ_ONLY`: Reads local database telemetry. No network calls. Always allowed.
  - `PASSIVE`: Passive scanning (ZAP HAR import, Semgrep local SAST). No target requests.
  - `ACTIVE_SAFE`: Non-mutating GET requests (rate-limit probes, account checks). Consumes request budget.
  - `MUTATING_APPROVAL`: State-changing HTTP methods (POST, PUT, PATCH, DELETE). Pauses execution and prompts operator for interactive approval.
- **Emergency Stop**: Abort signals are monitored across all loops and subprocesses; an emergency stop terminates pending operations within milliseconds.

---

## 5. Model Serving & Context Architecture

- **Primary Reasoning Model**: DeepHat-V1-7B.
- **Inference Server**: Remote vLLM instance connected via SSH tunnel at `127.0.0.1:18001/v1`.
- **Context Handling**:
  - Extended to 100,000 context tokens via 4x YaRN.
  - Preflight prompt tokenization via `/tokenize`.
  - Output reserve of 2,048 tokens strictly enforced.
  - Schema-constrained output using `zod-to-json-schema` and vLLM guided JSON decoding.
  - **Context Pruning**: Investigation context uses selective evidence summaries rather than raw unbounded HTTP traffic.

---

## 6. Model Benchmark & Research Harness

The benchmark harness operates in a dedicated, parallel mode without altering the client-facing audit flow:

```
[Ground-Truth Fixture] -> [Sanitized Evidence Bundle]
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
[Prompt: default]        [Prompt: correctness-review]      ...
         |                         |                         |
         +-------------------------+-------------------------+
                                   |
    +--------------+---------------+--------------+----------------+
    |              |               |              |                |
[DeepHat-V1-7B]  [GPT-4o]    [Gemini 2.0]   [Groq Llama-3]   [WhiteRabbitNeo]
    |              |               |              |                |
    +--------------+---------------+--------------+----------------+
                                   |
                   [Refusal & Hedging Classifier]
                     (Flags 'declined' status)
                                   |
                   [Agent 5 Verification Engine]
               (Proves/refutes candidate hypotheses)
                                   |
                  [Ground-Truth Scoring Engine]
            (Precision, Recall, F1, Repeat Hit-Rate)
                                   |
                   [Benchmark Comparison Report]
                        (Markdown & JSON)
```

- **Model Providers**: DeepHat (vLLM), OpenAI (GPT-4o), Google Gemini (Gemini 2.0 Flash), Groq (Llama 3.3 70B), and WhiteRabbitNeo (vLLM).
- **Extended Finding Attribution**: Findings in benchmark mode track `source_model`, `prompt_variant_id`, `raw_confidence_text`, and `verifier_result`.
- **Four-State Lifecycle**: Adds the terminal state `declined` to separate safety filter refusals/hedging from true analytical misses.
- **Repeat Runs & Consistency**: Measures per-finding hit rates across $N$ repeats (e.g. 4/5 = 80%).
- **Verification Reuse**: Reuses the deterministic Agent 5 `VerificationEngine` unchanged for all model outputs.
---

## 7. OAuth & Authenticated Session Hydration

To audit web applications requiring OAuth/SSO (Google, GitHub, Okta, Auth0, Keycloak) without violating third-party anti-bot boundaries or CAPTCHAs, TraceHawk implements a 3-tier authenticated session hydration subsystem:

```
[User / CI/CD] ─────────────────────────────────────────────────────────┐
      │                                                                  │
      ▼ (Interactive Handshake)                                          ▼ (Pre-Authenticated)
[AuthProfileManager.recordInteractiveOAuth]             [Exported storageState / Bearer JWT]
      │                                                                  │
      ▼                                                                  ▼
[artifacts/auth-profiles/<slug>.json] ◄──────────────────────────────────┘
      │
      ▼ (Session Hydration)
[browser.newContext({ storageState })]
      │
      ▼ (Extra Auth Headers: Authorization: Bearer <token>)
[PlaywrightCrawler / BrowserManager]
      │
      ▼
[Full Authenticated Crawl, BOLA/IDOR Testing, and Deep Vulnerability Auditing]
```

- **Interactive OAuth Handshake:** Dedicated visible Chrome launch allows the user to complete Google/GitHub/SSO authentication (including MFA/2FA) once. The engine waits for navigation back to the target origin, captures `context.storageState()`, and saves it as an auth profile.
- **`storageState` Hydration:** Crawlers and agents ingest the saved cookies and localStorage tokens natively into `browser.newContext({ storageState })`, bypassing the login page and testing protected internal routes.
- **Bearer Token & API Profile Generation:** Directly synthesizes authentication profiles for SPAs and REST APIs from raw OAuth JWTs via `AuthProfileManager.createBearerProfile()`.
- **RBAC & BOLA Cross-Testing:** Allows agents to run with multiple user profiles (e.g., standard user vs. admin vs. unauthenticated) to verify access control boundaries.



