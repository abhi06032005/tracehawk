# TraceHawk Phase 2 strict implementation review

**Historical review of the implementation before fixes.** The issues below motivated the subsequent implementation. See [PHASE2.md](PHASE2.md) for the current behavior and [PHASE2-VALIDATION.md](PHASE2-VALIDATION.md) for verification results. The regression test file has been updated to validate the repaired contracts.

Review date: 27 October 2026. Verdict: NOT COMPLETE; not acceptable as a working, evidence-driven DeepHat investigation agent.

Scope: source inspection, TypeScript checks, existing isolated unit tests, and eight additional isolated regression checks. No production source or recorder files were modified. No live model, PostgreSQL integration, browser flow, or Juice Shop run was validated. The existing integration suites were not run: they perform live requests against example.com and do not establish the requested authorized Juice Shop workflow. No Git repository was available to compare recorder behavior against an earlier revision.

## Blocking findings

1. **P1 — DeepHat receives no evidence.** `apps/server/src/ai/agent.ts:435-440` sends hypothesis titles/status and step labels/thoughts/tool names, excluding every `toolResult`. Even the initial endpoint inventory never reaches the model. Tool argument schemas are omitted from its prompt. Results therefore cannot inform the next model decision. `get_session_evidence` returns only counts and up to 60 exchange summaries, not the required complete context.
2. **P1 — Unsupported claims become VERIFIED.** `agent.ts:245` and `:263` directly persist model-provided status with no evidence gate. The evaluator at `:650` treats anonymous HTTP 200 as proof of missing authentication; `:671` treats no observed throttle in a tiny sample as proof of absent rate limiting. A denied/error result also satisfies that rate-limit condition because both properties are undefined. Evaluation selects hypotheses by title fragment rather than binding the result to the affected endpoint. Evidence IDs are not resolved or checked for session ownership.
3. **P1 — Scope enforcement is bypassable.** `apps/server/src/ai/tools.ts:196-198` uses substring checks for localhost/127.0.0.1, authorizing unrelated hostnames containing those strings and other local ports. Both active fetches follow redirects without destination revalidation. `agent.ts:277` spreads model arguments after the trusted session ID, allowing it to override the investigation session and its scope.
4. **P1 — State-changing execution has no approval gate.** `tools.ts:380-403` executes model-selected POST, PUT, PATCH and DELETE after only an origin check. Rate checks also accept POST. No explicit active-test authorization record, approval workflow, or investigation-wide request budget exists. The five-request cap applies to each rate-tool invocation only. Start-route limits are unbounded parseInt values (`routes/api.ts:400-403`).
5. **P1 — Secret exclusion is not guaranteed.** `apps/server/src/utils/redact.ts` returns form bodies and non-JSON text unchanged; malformed/truncated JSON also returns unchanged. JSON email/phone fields are retained, and ordinary cookie names preserve value prefixes. Console messages are persisted verbatim by the recorder. Tool results and model decisions are persisted without a final sanitization boundary (`agent.ts:288`, `:718`). The current agent omits evidence entirely from model calls, so this review does not claim the tested form password was actually transmitted to a model; sending the currently named sanitized evidence would not be safe.
6. **P1 — Emergency stop does not stop in-flight tools.** The auth probe uses an independent five-second signal, not the investigation signal (`tools.ts:403`). Rate-tool fetch has neither a timeout nor a cancellation signal (`:454`). Cancellation is checked only between requests. Thus a tool can continue after cancellation, or hang beyond the global deadline. Model abort errors are swallowed into fallback reasoning; outer failures can also overwrite CANCELLED with FAILED.
7. **P1 — Disabled/failed AI silently becomes a scripted investigation.** `agent.ts:373-388` falls back for disabled AI, HTTP errors and invalid responses. `:489-609` prescribes tools and hypotheses by step number and reports DeepHat completion. This does not satisfy the requirement that DeepHat select tools and evaluate returned evidence. The autonomous fetch at `:444-448` omits AI_API_KEY authorization, although the separate summary provider implements it. Appending `/v1/chat/completions` also mishandles base URLs that already end in `/v1`.
8. **P2 — Two named tools do not implement their promised capability.** `tools.ts:357-377` invokes two local rule functions rather than OWASP ZAP, reports a fixed rule count, and drops finding evidence references. `compare_test_account_access` makes one unauthenticated probe, with no two-account comparison or resource-ownership baseline.
9. **P2 — Lifecycle, UI and audit history are incomplete.** Start accepts any existing session, including RECORDING/PAUSED (`agent.ts:86-95`). The dashboard shows steps, outputs, statuses, confidence, risk summary and remediation, but does not render supportingEvidenceIds or navigable finding evidence; its prerequisites heading displays only attackMechanism. Tool exceptions are console-only (`agent.ts:308-310`); model failures and full decisions are not durably recorded; status changes overwrite hypotheses without an immutable evaluation history. The final tool result need not reach another model call when the step cap is reached or isFinished is already true.

## Requirement-by-requirement assessment

| # | Requirement | Assessment |
|---|---|---|
| 1 | PostgreSQL evidence connected to AI | Partial: backend reads evidence, but model prompt omits it. |
| 2 | Four environment variables / compatible client | Partial: variables exist; autonomous requests ignore API key. |
| 3 | Completed-session structured context | Fail: no completion check; incomplete inventory; no complete request/response, auth, storage, console, WebSocket and passive-finding context reaches the model. |
| 4 | Never send secrets or private information | Fail acceptance: incomplete sanitization and no enforced outbound boundary. Actual live transmission was not tested. |
| 5 | Model hypotheses, mechanisms, prerequisites, impact, tools | Partial: prompt/schema fields exist; model lacks evidence and important fields are optional. |
| 6 | Zod JSON validation and evidence references | Partial: structure validated; IDs are unchecked strings and several tool results omit references. |
| 7 | Central observe/analyze/plan/verify/evaluate loop | Partial: a real loop exists, but scripted fallback and missing evidence feedback violate intended operation. Phase ordering is prompted, not enforced. |
| 8 | Eight typed tools | Partial: all eight names and argument schemas exist; ZAP and account comparison are incomplete. |
| 9 | Backend tools, no arbitrary model commands | Implemented in inspected dispatch: fixed switch and Zod argument parsing; no model-generated shell execution found. |
| 10 | Allowlists, authorization, budgets, timeouts, approvals | Fail: bypassable scope, no approval gate or cumulative request budget; incomplete timeouts. |
| 11 | History and evidence back after every result | Fail: tool results persist but are excluded from model messages; exceptions lack durable history. |
| 12 | Maximum steps/time, cancel/emergency stop | Partial: controls exist, but in-flight tools do not consistently obey cancellation/timeouts and limits lack server bounds. |
| 13 | Four verification states | Partial: states exist in schema/UI but VERIFIED and REJECTED assignments are not evidence-safe. |
| 14 | AI Audit dashboard | Partial: wired API/SSE/polling and output controls exist; linked evidence and reliable statuses are missing. No browser rendering test performed. |
| 15 | Complete decisions/results persisted without secrets | Partial: Prisma models and writes exist; missing decisions/errors/history and incomplete redaction. Live persistence not validated. |
| 16 | Juice Shop initial authorized target | Not demonstrated: README examples only; no Juice Shop service, dedicated fixture, authorization setup or integration test found. |
| 17 | Evaluation tests prevent unsupported verification | Fail: existing test covers a simulated 401 rejection; three new evaluation counterexamples incorrectly become VERIFIED. |
| 18 | Other OpenAI-compatible endpoints | Partial: configurable model/base URL, but autonomous API-key omission and fixed path assumptions break common setups. No endpoint compatibility tests found. |

## Checks executed

- `npm exec --workspace=apps/server -- vitest run src/utils/redact.test.ts src/security/rules.test.ts`: 16 passed.
- Server and web `tsc --noEmit`: both completed successfully.
- `npm exec --workspace=apps/server -- vitest run src/ai/phase2-review.test.ts`: 8 failed, reproducing the defects below. Database and fetch are mocked; no real active security probes were issued.

| Regression expectation | Actual result |
|---|---|
| Public HTTP 200 does not prove missing authentication | VERIFIED |
| Three unthrottled requests do not prove absent rate limiting | VERIFIED |
| Denied rate-limit tool does not verify a vulnerability | VERIFIED |
| Unrelated hostname containing localhost is denied | Allowed |
| DELETE requires approval before network execution | Fetch invoked without approval |
| Model receives returned tool evidence | Evidence omitted |
| Form password is redacted | Password retained |
| Private JSON email is redacted | Email retained |

The added regression test file intentionally fails until these defects are fixed. Passing the existing suite or type checks is not sufficient to accept Phase 2. First fix evidence delivery, verification gates, scope/approval enforcement, redaction and cancellation; then prove the actual model/PostgreSQL/Juice Shop workflow with integration tests.
