# Phase 2: model-driven investigations

## Start locally

1. Start Docker Desktop, then run `docker compose --profile security-test up -d` from the repository root. PostgreSQL, Juice Shop and a dedicated ZAP instance bind only to loopback ports 5433, 3000 and 8080. The development ZAP key is deliberately local-only; change it in both Docker Compose's environment and the backend environment for other installations.
2. Run `npm run db:generate` and `npm --workspace=apps/server run db:deploy` for a new database. For an existing Phase 1 database created with `db push`, back it up and first baseline the existing schema with `npm exec --workspace=apps/server -- prisma migrate resolve --applied 202610270001_baseline`; then deploy the remaining migrations. Do not baseline a database that does not match the original schema.
3. Configure `apps/server/.env` with the settings below. Keep AI_ENABLED=false until a model is deployed. The root .env is also read by Docker Compose; npm workspace commands run from apps/server and use its .env.
4. Run `npm run dev`. Create a project targeting `http://127.0.0.1:3000` with that exact allowed origin. Record the browser session normally, then stop it.
5. Open AI Audit, select the completed session, review its allowed origins and grant explicit authorization. Live request permission is separate from passive inspection. Set the shared request budget, model-turn limit and execution deadline, then start.

```env
AI_ENABLED=false
AI_BASE_URL=http://127.0.0.1:8000/v1
AI_MODEL=DeepHat-V1-7B
AI_API_KEY=
AI_JSON_MODE=true
ZAP_BASE_URL=http://127.0.0.1:8080
ZAP_API_KEY=tracehawk-local-test-key
ZAP_IMPORT_DIR=../../zap-import
ZAP_CONTAINER_IMPORT_DIR=/zap/import
AI_TEST_ACCOUNTS=[]
AI_ACCESS_SCENARIOS=[]
```

AI_BASE_URL may be a root URL, an API prefix such as /v1 or /api/v2, or a complete /chat/completions URL. AI_API_KEY is sent only to that endpoint as a Bearer header. Set AI_JSON_MODE=false for compatible endpoints that reject response_format; JSON output is still strictly validated. Model calls have a 45-second timeout and response-size bound.

## Loop and proof rules

The backend records OBSERVE, asks the model to ANALYZE, records its PLAN, executes the selected tool in VERIFY, and sends the actual result back for EVALUATE. Evaluation may plan another tool or finish. The final allowed model turn cannot schedule another tool, ensuring every completed tool gets an evaluation opportunity. If a model/network failure or cancellation interrupts evaluation, the failed/cancelled status and tool history remain visible; completion is not claimed.

All decisions, proposed statuses, accepted statuses, results, failures, approvals and limits are stored in PostgreSQL. Model turns are capped at 30, duration at 600 seconds, and cumulative active requests at 50. Each rate-tool call is capped at five requests. Tool redirects are never followed. Timeouts and emergency stop abort in-flight model and target requests. Interrupted investigations are marked failed on server restart and pending approvals expire.

The model proposes hypotheses and evaluates evidence; a backend proof gate controls final status. VERIFIED requires a backend-issued evidence ID matching the same claim type and endpoint. Supported automatic proofs are missing CSP, missing HSTS on HTTPS, and the configured two-account ownership test. Other claims remain hypotheses/needs verification. Public HTTP 200, a few responses without HTTP 429, credential-like storage key names and ZAP alerts alone never prove an exploitable vulnerability. REJECTED also requires exact counterevidence; errors and unavailable tools are inconclusive.

The phase-event count may exceed the model-turn limit because each turn creates multiple history events.

## Privacy and permissions

The model receives opaque endpoint references and exchange IDs, complete method/status inventory, payload shapes with scalar values omitted, security-header facts, auth observations, storage/cookie flags, console error categories, WebSocket direction/length metadata and passive-finding metadata. Arbitrary path/query values, payload text, console text, cookies and credentials are not sent. This deliberately limits semantic inspection of personal content. Evidence source IDs remain available for local inspection. Legacy cookie snapshots without flags explicitly report them as unavailable.

Active tools accept exchange IDs or operator-defined scenario IDs, never model-provided credential values or session IDs. The backend resolves the target from its bound session and checks the exact explicit origin. Localhost aliases and other ports require their own allowlist entries. A project origin does not authorize another origin reached through redirects. Read-only inspection does not require active-test permission.

POST/PUT/PATCH/DELETE rate probes require an additional, single-use approval displayed with the exact exchange, endpoint reference, method and request count. They send no recorded body or credentials. Approval expires on stop/deadline and cannot be reused or applied to another investigation. These methods can change data even with an empty body. Budget is reserved before sending each request, including failed requests.

The local control API requires the X-TraceHawk-Control header for audit mutations and rejects foreign-origin mutations. The untrusted Juice Shop origin is not a control origin. The app is a local, single-server tool, not a multi-user hosted service.

## Two-account access scenarios

Set AI_TEST_ACCOUNTS and AI_ACCESS_SCENARIOS as JSON in the **backend environment only**. Example shape (replace placeholders locally; do not commit real credentials):

```json
[{"id":"owner","origin":"http://127.0.0.1:3000","headers":{"Authorization":"Bearer OWNER_TEST_TOKEN"}},{"id":"other","origin":"http://127.0.0.1:3000","headers":{"Authorization":"Bearer OTHER_TEST_TOKEN"}}]
```

```json
[{"id":"owner-resource","endpoint":"http://127.0.0.1:3000/api/your-protected-resource","ownerAccountId":"owner","otherAccountId":"other","resourcePointer":"/data/id","expectedResourceValue":123,"otherMustBeDenied":true}]
```

The operator must establish that the resource belongs to the owner and the other account must not access it. The tool uses two distinct credentials, pins both to the target origin, and compares the specified JSON pointer to the operator-supplied resource identity. A valid owner baseline plus the same resource returned to the non-owner supports cross_account_access; a valid baseline plus HTTP 401/403 for the other account refutes that specific scenario. Other outcomes remain inconclusive. Private response values are used transiently for comparison and are never persisted or sent to the model.

## ZAP passive integration

The dedicated scanner imports a HAR file from the shared directory and waits for its passive-scan queue before fetching alerts. It never calls a spider, active scanner or replay API. Imported URLs use a unique synthetic host and source exchange IDs, so results cannot mix with prior investigations. Only safe security-header semantics are imported; response bodies and cookies are omitted. This is a limited configuration review, not a full-content ZAP scan. Alerts retain source IDs and remain unverified. Missing configuration, scanner contention, timeouts and failures are visible tool outcomes.

References: [ZAP HAR import](https://www.zaproxy.org/faq/how-can-you-import-post-requests/), [ZAP API and passive scanning](https://www.zaproxy.org/docs/api/).

## Validation

- `npm test`: isolated evaluation/privacy/argument tests plus local HTTP fixture-model/target tests. No external target or deployed model is used; the HTTP fixture exists only inside tests.
- `npm --workspace=apps/server run test:integration`: actual PostgreSQL and headless Playwright recorder against the authorized local Juice Shop; the inference endpoint is a local fixture. Test-created database rows are deleted afterward.
- In PowerShell, set `$env:TEST_ZAP='true'` before test:integration to additionally test the real ZAP container. Remove the variable afterward.
- `npm --workspace=apps/server run test:recorder`: the original visible-browser integration suite, now pointed at local Juice Shop rather than a third-party website.
- `npm run build`: backend compilation and production dashboard build.

A fixture-model pass proves protocol, permissions, persistence and control flow. It does not validate DeepHat's reasoning quality or performance; those require the deployed model.

## Recording and token inspection (28 October 2026)

Start from the dashboard URL field and open the dedicated recording window. TraceHawk prefers installed Chrome and falls back to bundled Chromium when Chrome is unavailable. Unrelated personal tabs are outside this dedicated browser context. The session inspector supports request search, API filtering, pause/resume/stop, browser focus, storage, console, and token observations.

Raw token values remain in a bounded backend memory vault for up to 30 minutes. Local reveal requires the control header; the dashboard masks the value again after 20 seconds. Restarting the backend or deleting the session removes access to those values. Saved token observations contain security metadata. Outbound model tools further restrict those observations to typed, allowlisted facts; decoded JWT metadata does not verify signatures or prove exploitability.

The provider also supports Hugging Face via AI_PROVIDER=huggingface and HF_TOKEN. A populated HF_TOKEN currently selects Hugging Face even if AI_PROVIDER is custom. Fixture tests explicitly clear HF_TOKEN to prevent paid inference. No real provider was contacted during this validation.
