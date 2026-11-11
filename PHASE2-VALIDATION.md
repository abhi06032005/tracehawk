# Phase 2 validation — 28 October 2026

Validated in D:\tracehawk with local test services:

- Unit and local fixture tests: 71 passed, including four new token privacy, session isolation, expiry/deduplication, JWT metadata and outbound allowlist checks.
- Visible recorder integration: 8 passed.
- PostgreSQL and real ZAP integration: 2 passed. Captured 44 real Juice Shop exchanges and 5 durable audit phase events; an unsupported verified claim was gated.
- Audit dashboard browser check: passed consent, completed-session filtering, approval denial, evidence links, prerequisites and runtime-error checks.
- Production build: backend and all frontend routes compiled; final build completion recorded in chat.

The first restricted fixture run could not connect to loopback. A permitted rerun passed. Docker was initially stopped; integration passed after starting Docker Desktop and the existing Compose test services.

Changes include the missing storage route closure, token inspector type fixes, typed outbound token metadata, fixture-provider isolation, pause-aware asynchronous token capture, visible retry errors across data pages, and corrected Settings status wording.

Limits: no deployed DeepHat or Hugging Face reasoning was tested and no inference credits were used. The new raw-token vault checks use mocked persistence; a dedicated full browser-to-database token reveal/privacy scenario and a complete responsive visual review remain outstanding. Existing recorder integration exercises the real browser, persistence, pause/resume and stop flow but does not cover all token sources.

## Live DeepHat upgrade — 28 October 2026

Supersedes the earlier no-live-model limitation: the user authorized real inference on the existing Vast.ai model. Deployed a supervised native 32768-token vLLM service preserving FP16 cached weights and the custom Jinja template. Through the Windows tunnel, a 28841-token prompt generated valid output. Real passive audit completed all five phases with two hypotheses and zero active requests; temporary project cleaned up. Added exact token budgeting, schema-constrained output, explicit local-provider precedence, configurable time/output limits and diagnostic errors. Details: DEEPHAT.md.

Final upgrade checks: 77 unit/fixture tests passed, production server/web build passed, and audit UI browser checks passed. Live service advertises 32768 tokens. No model reinstall or new model download was performed.

100k follow-up: vLLM advertises 100000 tokens using 4x YaRN (native baseline 32768). A 96463-token live prompt passed generation and three-position exact marker retrieval. The strengthened audit prompt completed a real passive investigation with one hypothesis and zero active requests. 77 fixture tests and production build passed. Audit and affected session pages both returned HTTP 200 after production build with development cache isolated in .next-dev. One synthetic retrieval test does not establish general security-analysis accuracy at extended context lengths.

One-click reporting update: removed report consent/limit controls; default passive mode, 20 turns, no overall deadline (maxTimeSeconds=0, deadline=NULL) and AI_REQUEST_TIMEOUT_MS=0. Stop remains available. Saved AI reports history and JSON download expose durable investigation/hypothesis/step records. 78 fixture tests and production build passed; real PostgreSQL integration passed with an unlimited-time report, nonempty saved summary and 5 persisted events (ZAP test skipped in this run).
