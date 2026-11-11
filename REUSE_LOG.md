# DeepHat / TraceHawk — Open-Source Code Reuse & Integration Log

This log documents all existing modules reused, external open-source projects integrated, licenses, and justifications for custom code, adhering strictly to the principle: **Maximum Code Reuse, Minimum Rewriting, Maximum Functional Improvement**.

---

## 1. Existing Modules Reused

| Module | Location | Original Functionality | Status & Reuse Strategy |
|---|---|---|---|
| **DeepHat Inference Provider** | `apps/server/src/ai/provider.ts` | vLLM OpenAI-compatible client, 100k YaRN context checking, tokenizer preflight, guided JSON decoding | **Reused 100% as primary reasoning model**. No second LLM introduced. Preserved remote GPU serving at `127.0.0.1:18001/v1`. |
| **Playwright Browser Manager** | `apps/server/src/browser/manager.ts` | Headed Playwright Chromium, profile persistence (`.tracehawk-profile`), session lifecycle | **Reused & Extended**. Serves as the browser execution core for both manual recording and automated crawling. |
| **Telemetry Session Recorder** | `apps/server/src/browser/recorder.ts` | CDP network interception, status codes, timings, headers, request/response bodies | **Reused 100%**. Collects raw network observations for all analysis engines. |
| **Storage & Cookie Snapshots** | `apps/server/src/browser/storage.ts` | HTML5 `localStorage`, `sessionStorage`, and Cookie extraction | **Reused 100%**. Provides storage telemetry for security auditing. |
| **Ephemeral Token Vault** | `apps/server/src/browser/credentials.ts` | In-memory token vault (30-min TTL, 100 entries max), JWT metadata extraction, local reveal | **Reused 100%**. Preserves strict privacy boundary while allowing operator inspection. |
| **Deterministic Passive Rules** | `apps/server/src/security/rules.ts` | 8 passive audit rules (CSP, HSTS, insecure cookies, CORS, stack traces, version disclosure) | **Reused 100%**. Retained as the baseline deterministic vulnerability discovery layer. |
| **ZAP HAR Import & Scanner** | `apps/server/src/ai/zap.ts` | Synthetic HAR export, docker container execution, alert querying | **Reused & Extended**. Provides passive scanning through OWASP ZAP. |
| **Evidence Gating Core** | `apps/server/src/ai/contracts.ts` | Zod schema validation, phase state machine, `gateHypothesis` evidence enforcement | **Reused 100%**. Ensures model claims cannot become verified vulnerabilities without backend proofs. |
| **Interactive Report Q&A** | `apps/server/src/ai/chat.ts` | Conversational post-audit analysis grounded strictly in stored investigation evidence | **Reused 100%**. |

---

## 2. External Projects Integrated or Adapted

| Project | Upstream URL | Upstream License | Version / Image | Integration Pattern |
|---|---|---|---|---|
| **OWASP ZAP** | https://github.com/zaproxy/zaproxy | Apache-2.0 | `ghcr.io/zaproxy/zaproxy:stable` | **Docker Container + REST API**: Ingests privacy-projected HAR files without direct network replay; queries `/JSON/pscan/view/recordsToScan/` and `/JSON/core/view/alerts/`. Extended in Phase 2 for active spidering within allowlisted scope. |
| **Playwright** | https://github.com/microsoft/playwright | Apache-2.0 | `^1.50.1` | **Direct Node.js API**: Extended in `PlaywrightCrawler` (`apps/server/src/browser/crawler.ts`) for autonomous link, button, and form enumeration with technology detection and auth route identification. |
| **Nuclei** | https://github.com/projectdiscovery/nuclei | MIT | `v3.x` | **CLI Subprocess Adapter**: Integrated in `NucleiScannerAdapter` (`apps/server/src/security/scanners/nuclei.ts`) with strict rate limiting (max 25 req/s), policy gateway scope validation, and streaming JSON-lines output parsing. |
| **Semgrep** | https://github.com/semgrep/semgrep | LGPL-2.1 (Engine) / Community Rules | `1.x` | **CLI Subprocess Adapter**: Integrated in `SemgrepScannerAdapter` (`apps/server/src/security/scanners/semgrep.ts`) for polyglot static application security testing (SAST). Invoked as an external binary to prevent LGPL license taint. |
| **Trivy** | https://github.com/aquasecurity/trivy | Apache-2.0 | `0.58.x` | **CLI Subprocess Adapter**: Integrated in `TrivyScannerAdapter` (`apps/server/src/security/scanners/trivy.ts`) for software composition analysis (SCA) scanning dependency lockfiles for known CVEs. |
| **Gitleaks** | https://github.com/gitleaks/gitleaks | MIT | `8.x` | **CLI Subprocess Adapter**: Integrated in `GitleaksScannerAdapter` (`apps/server/src/security/scanners/gitleaks.ts`). Secrets are strictly redacted immediately upon ingestion; only metadata and fingerprints are stored. |
| **Strix** | https://github.com/usestrix/strix | Apache-2.0 | Reference Commit (2026) | **Pattern & Schema Reuse**: Adapted multi-agent role decomposition, tool argument schemas, and vulnerability verification prompts to TypeScript and DeepHat-V1-7B constraints. |
| **Shannon** | https://github.com/KeygraphHQ/shannon | **AGPL-3.0** | Reference Pattern | **Clean-Room Design Reference**: *Zero source code copied* due to AGPL-3.0 copyleft obligations. Emulated its source-aware route extraction and verification workflows natively in clean TypeScript. |
| **PentAGI** | https://github.com/vxcontrol/pentagi | MIT | Reference Commit (2026) | **Architecture Pattern**: State machine handoff between reconnaissance, execution, and verification phases. |

---

## 3. New Modules Created & Justification

| File | Purpose | Why Custom Code Was Necessary |
|---|---|---|
| `apps/server/src/security/policy.ts` | **Security Policy Gateway** (`SecurityPolicyGateway`) | External tools do not understand TraceHawk's permission boundaries, target scopes, or human-in-the-loop approval requirements. Enforces allowlists, SSRF/metadata guards, request budgets, and risk tiers (`READ_ONLY`, `PASSIVE`, `ACTIVE_SAFE`, `MUTATING_APPROVAL`). |
| `apps/server/src/security/findings.ts` | **Finding Normalization & Deduplication** | Unifies the split between deterministic passive findings (`Finding`) and AI hypotheses (`AiHypothesis`). Provides the standard 5-status lifecycle (`discovered`, `needs_verification`, `verified`, `false_positive`, `inconclusive`) and deduplication by endpoint/CWE. |
| `apps/server/src/browser/crawler.ts` | **Autonomous Playwright Crawler** (`PlaywrightCrawler`) | Enables systematic route, button, and form enumeration within authorized target scopes without requiring manual user browsing. |
| `apps/server/src/security/scanners/semgrep.ts` | **Semgrep SAST Adapter** | Adapts Semgrep CLI output into normalized security findings with CWE mappings. |
| `apps/server/src/security/scanners/trivy.ts` | **Trivy SCA Adapter** | Adapts Trivy dependency vulnerability reports into normalized findings. |
| `apps/server/src/security/scanners/gitleaks.ts` | **Gitleaks Secret Scanner Adapter** | Adapts Gitleaks output, strictly scrubbing secret values before storage. |
| `apps/server/src/security/scanners/source-scanner.ts` | **Unified Source Security Scanner** | Aggregates and deduplicates static, dependency, and secret findings for authorized repositories. |
| `apps/server/src/security/scanners/nuclei.ts` | **Nuclei Scanner Adapter** | Executes YAML template vulnerability scans with rate limiting and scope protection. |
| `apps/server/src/security/verifier.ts` | **Evidence Verification Engine** (`VerificationEngine`) | Deterministically proves or refutes potential findings (CORS, headers, rate-limiting, BOLA) to eliminate false positives. |
| `apps/server/src/reporting/generator.ts` | **Multi-Format Report Generator** (`ReportGenerator`) | Generates structured JSON, technical/executive Markdown, and print-ready styled HTML reports. |
| `apps/server/src/benchmark/types.ts` | **Benchmark Harness Types & Contracts** | Standardizes `ModelProvider`, `EvidenceBundle`, `PromptTemplate`, `GroundTruthFixture`, and scoring results. |
| `apps/server/src/benchmark/refusal-classifier.ts` | **Refusal & Hedging Classifier** (`RefusalClassifier`) | Scans model outputs for safety refusals and hedging disclaimers, mapping them to the `declined` lifecycle state. |
| `apps/server/src/benchmark/prompts.ts` | **Prompt Template Engine** | Provides standardized `default` security audit and `correctness-review` software defect prompts. |
| `apps/server/src/benchmark/providers/` | **Multi-Model Adapters** | Implements adapters for DeepHat-V1-7B, OpenAI GPT, Google Gemini, Groq, and WhiteRabbitNeo. |
| `apps/server/src/benchmark/scorer.ts` | **Ground-Truth Scorer & Repeat Tracker** | Diffs model findings against cataloged ground-truth vulnerabilities, calculating precision, recall, F1, and repeat hit-rates. |
| `apps/server/src/benchmark/reporter.ts` | **Benchmark Comparison Reporter** | Generates Markdown and JSON comparison matrices across models, prompt variants, latency, and costs. |
| `apps/server/src/benchmark/runner.ts` | **Benchmark Orchestration Runner** | Coordinates repeats, models, prompt variants, and routes findings through the existing Agent 5 verifier. |
| `apps/server/src/benchmark/cli.ts` | **Benchmark CLI Entrypoint** | Command-line interface for running automated benchmark evaluations. |

---

## 4. License Compliance Summary

1. **Apache-2.0 Compatibility**: TraceHawk and its dependencies (Playwright, Trivy, Strix, ZAP) are fully compatible under Apache-2.0.
2. **MIT Compatibility**: Nuclei, Gitleaks, and PentAGI use the permissive MIT license, which allows commercial and proprietary integration without restrictions.
3. **LGPL-2.1 Isolation**: Semgrep is invoked as an isolated command-line subprocess (`semgrep scan --json`). No static or dynamic linking against LGPL libraries occurs within Node.js, preserving Apache-2.0 licensing.
4. **AGPL-3.0 Safeguard**: Shannon is licensed under AGPL-3.0. No code, scripts, or assets from Shannon are included in this repository. All source-code-aware analysis concepts are independently implemented clean-room.

---

### Component: OAuth & Session State Hydration Subsystem
- **Module:** `apps/server/src/browser/auth-manager.ts` (`AuthProfileManager`)
- **Upstream Pattern:** Playwright native `storageState` session hydration and Strix/Shannon authenticated multi-role audit patterns.
- **License:** Apache-2.0
- **Purpose:** Enables autonomous agents to audit OAuth/OIDC/SSO-protected web applications (Google, GitHub, Auth0, Okta, Keycloak) without tripping third-party IdP bot protections, CAPTCHAs, or MFA barriers.
- **Key Capabilities:**
  1. Interactive one-time OAuth handshake recorder (`recordInteractiveOAuth`).
  2. Native Playwright `storageState` JSON persistence in `artifacts/auth-profiles/`.
  3. Direct Bearer token & JWT profile generation (`createBearerProfile`).
  4. Automatic context hydration for `PlaywrightCrawler` and `BrowserManager`.
  5. REST API management (`/api/auth/profiles`, `/api/auth/interactive-login`).

