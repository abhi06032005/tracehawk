# DeepHat local integration

TraceHawk reaches the existing Vast.ai RTX 3090 through the Windows SSH tunnel at `http://127.0.0.1:18001/v1`. Remote vLLM listens only on `127.0.0.1:8001`.

## Deployment

Supervisor service: `tracehawk-deephat`. Launch script: `/workspace/tracehawk-deephat-serve.sh`. Log: `/workspace/tracehawk-deephat.log`. Repository copies: `scripts/deephat-serve.sh` and `scripts/deephat-supervisor.conf`.

The launch preserves cached FP16 DeepHat weights and `/workspace/deephat-chat.jinja`. It uses 100000 context tokens via 4x YaRN extension, one concurrent sequence, 90% GPU utilization, eager execution, and 2048 batched prefill tokens. The prefill batch size does not limit context length. Offline mode prevents another model download. Do not start the old manual command alongside this service.

```bash
supervisorctl status tracehawk-deephat
supervisorctl restart tracehawk-deephat
tail -n 50 /workspace/tracehawk-deephat.log
```

Supervisor restarts after an unexpected exit. Instance stop/start preserves the configuration; recycle/destruction may remove it. Retain repository copies and the custom template.

## Configuration

Root `.env` and `apps/server/.env`:

```dotenv
AI_ENABLED=true
AI_PROVIDER=custom
AI_BASE_URL=http://127.0.0.1:18001/v1
AI_MODEL=DeepHat/DeepHat-V1-7B
AI_API_KEY=dummy
AI_CONTEXT_TOKENS=100000
AI_MAX_OUTPUT_TOKENS=2048
AI_REQUEST_TIMEOUT_MS=0
AI_TOKENIZER_URL=http://127.0.0.1:18001/tokenize
AI_JSON_MODE=schema
```

Explicit custom-provider selection overrides HF_TOKEN. Exact prompt tokenization reserves output space and checks the actual server limit. Evidence is never silently truncated. Schema-constrained output is derived from Zod; backend validation, tool permissions, phase transitions and evidence gates remain authoritative. Errors distinguish context overflow, tunnel/network failure, HTTP rejection, timeout, output truncation and invalid JSON/schema.

Reports start in one click with up to 20 model turns, no overall deadline, no model-response timeout, and no active-test requests. The model may finish early. Emergency stop remains available. An explicitly configured finite time limit is still supported by the backend. Later turns or very large sessions can exceed 100000 tokens; use a smaller recorded session in that case.

## Run and verify

Keep the existing SSH tunnel running, then run `npm run dev` from the root. When recreating the tunnel, retain your SSH host, port and key and add `-o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -N -L 127.0.0.1:18001:127.0.0.1:8001`. Do not start a duplicate tunnel on an occupied port.

`npm test` uses local fixtures without GPU inference. `npm run test:ai:live` explicitly uses the GPU: it verifies 100000 advertised tokens, generates with more than 90000 input tokens, records a temporary owned HTTP target, runs a real passive investigation, then deletes its temporary project. PostgreSQL and Playwright Chromium are required. Active-test request budget is zero.

Validated on 28 October 2026: 28841-token input generated valid output; a real audit completed OBSERVE, ANALYZE, PLAN, VERIFY and EVALUATE with two hypotheses and zero active requests. The RTX 3090 reported 6.55 GiB available KV cache and 122688 cache tokens at startup. This validates integration and execution, not universal accuracy of model-generated security conclusions.

Structured output format: [vLLM documentation](https://docs.vllm.ai/en/latest/features/structured_outputs/).

## 100k extension
The native model limit remains 32768. The launch uses YaRN factor 4, original_max_position_embeddings 32768, rope_theta 1000000, max_position_embeddings 131072, and an explicit serving cap of 100000. This is extrapolation, not native 100k training; quality can change, including on shorter prompts. See https://docs.vllm.ai/en/latest/features/context_extension/ for the extension mechanism. The output reserve remains 2048 tokens within the shared context budget.
The audit prompt now prioritizes attacker objectives, serious authorization/injection/session flaws, evidence-backed attack chains, prerequisites, expected secure behavior and concrete authorized verification steps. It must report coverage and uncertainty, not claim exhaustive discovery.
Development uses .next-dev while production uses .next so a production build cannot overwrite a running development server cache.

## Saved reports
Investigation rows store the summary and status; related hypotheses and steps store findings, decisions and evidence in PostgreSQL. Saved AI reports reload this data after refresh/restart. Download saved report exports the stored investigation as JSON. Deleting the source session deletes its related reports. Backend shutdown marks unfinished runs cancelled/failed; there is no automatic continuation after a restart.
