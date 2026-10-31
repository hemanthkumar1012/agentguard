# SentinelForge

**Policy enforcement, evaluation and observability for production AI agents.**

SentinelForge lets a company run AI agents that touch money and customer data. Every tool call is
decided before it executes (**allow, block, redact, rate-limit, require approval or escalate**), recorded as
tamper-evident evidence and traced end to end. Every agent version must pass release gates before it ships.

The reference deployment is **SentinelForge for fintech support operations**: an AI support agent for
"AcmePay" that can answer account questions and prepare refunds, but can never move money or read another
customer's data without verifiable authorization and risk-based human approval.

> Built on AgentGuard's deterministic enforcement core (identity, least privilege, scoped credentials, data
> inspection, risk, approvals, hash-chained audit, MCP boundary, OPA parity), extended with a declarative policy
> engine, an agent runtime, a multi-agent orchestrator, an evaluation engine and a trace explorer.

```text
User request ─► Agent plans a tool call ─► Policy gateway ─► allow / redact / rate-limit / approve / escalate / block
                    ▲                          │                       │
     untrusted text is taint-tracked           │                       └─► Tool sandbox (only if permitted)
                                               └─► hash-chained audit · trace spans · tokens · ₹ cost · latency
```

## What's inside

| Capability | What it does |
|---|---|
| **Policy-driven agent firewall** | Declarative YAML rules on agent, user, role, tenant, tool, action, arguments, amount, data sensitivity, resource ownership, injection signals, risk and environment. Six decisions; the strictest wins. Hot reload, dry-run simulation and a Rego mirror for OPA. |
| **Prompt-injection defense** | Taint tracking carries retrieved documents, tool output, DB fields, email and agent hand-offs into every later tool call. Normalised (unicode, zero-width, leetspeak) injection scoring. A deny rule for privileged actions. Output guard. |
| **Human approval workflow** | Approvals routed by role (`finance_manager`, `support_manager`, `compliance_officer`…) with the full proposed call and evidence. Approve, reject or request info. Bound to the exact request fingerprint, TTL, single use, no self-approval. Runs pause and resume. |
| **Agent runtime** | Versioned agents (model, prompt version, permissions, behaviour). A deterministic planner for CI, plus an OpenAI-compatible function-calling planner (OpenAI, Gemini, vLLM). Per-run scoped credentials. Token and ₹ budgets. |
| **Multi-agent orchestration** | Triage → policy / order / billing / escalation → responder. Each sub-agent has its own identity and minimal tools, and is reached through explicit delegation scopes. Billing can draft refunds but never issue them. |
| **Evaluation & release gates** | 156 original cases (support, prompt injection, PII leakage, tool misuse) run in per-case sandboxes. Scorecards for task success, tool selection, argument correctness, grounding, injection resistance, containment, privacy, policy compliance, reliability, cost and latency. Regression comparison and gated promotion. |
| **Trace explorer & observability** | Per-run timelines (LLM, retrieval, policy, tool, approval, guard, hand-off spans) linked to audit events and approvals. Search by tenant, version, user, status, tool or policy. Cost and latency dashboards, risk trends, Prometheus metrics, optional OpenTelemetry export. |
| **Red-team lab** | Attack-by-attack report: attack type, input source, agent response, attempted calls, policy decision, exposure, pass/fail, remediation. |

## Results

| Agent version | Change | Cases passed | Injection resistance | Containment | Release |
|---|---|---|---|---|---|
| `support-agent-v1.0` | Baseline: drafts refunds for finance | 156/156 | 100% | 100% | approved |
| `support-agent-v2.0` | Direct refunds, but obeys instructions in content | 81/156 | 27.0% | 100% | **blocked** |
| `support-agent-v2.1` | Direct refunds, regression fixed | 156/156 | 100% | 100% | approved |

The gateway contained every unsafe action v2.0 attempted, and the release gates still blocked it, because
an agent that relies on the backstop is a regression. Scores come from the deterministic planner used in CI;
evaluate `support-agent-llm` with an API key for real-model numbers (see
[evaluation methodology](docs/evaluation-methodology.md)).

The first v2.0 evaluation also found a real policy gap: a ₹5,000 refund with **no order id** was allowed.
It's now covered by the `refund-requires-order` rule and a dataset case.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the diagram and the request lifecycle.

```text
sentinelforge/ (this repository)
├── backend/app/
│   ├── gateway.py            # single enforcement point (baseline policy + rule engine, redaction, approvals, audit)
│   ├── policy_engine.py      # declarative rules, precedence, validation, rate limits
│   ├── injection.py          # injection scoring          redaction.py   # PII / secret redaction
│   ├── agent_runtime.py      # versions, planners, taint tracking, guarded tools, pause/resume, output guard
│   ├── orchestrator.py       # least-privilege multi-agent workflow
│   ├── evaluation.py         # datasets, sandboxes, scorers, release gates, comparisons
│   ├── tracing.py  prometheus.py  budgets.py  fintech.py
│   └── api/                  # runs, agent-versions, policies, traces, evaluations, redteam, orchestrations, …
├── backend/scripts/release_gate.py   # CI release gate
├── datasets/                 # 156 JSONL cases + deterministic generator
├── policy/rules/fintech_support.yaml # the live policy pack
├── policy/opa/               # Rego mirror + parity tests
├── supabase/migrations/      # durable schema (0004 adds traces, versions, evals, policy packs)
├── frontend/                 # Next.js console (server-side proxy; key never reaches the browser)
└── docs/                     # architecture, threat model, policy language, evaluation methodology, demo
```

## Run locally

### Backend

```bash
cd backend
python -m pip install -e ".[test]"
uvicorn app.main:app --reload --port 8000      # API docs at http://localhost:8000/docs
python -m pytest -q                            # 116 tests
python scripts/release_gate.py support-agent-v1.0
python scripts/release_gate.py support-agent-v2.0 --expect blocked
```

### Console

```bash
cd frontend
npm install
AGENTGUARD_BACKEND_URL=http://localhost:8000 AGENTGUARD_API_KEY=<operator key or empty in dev> npm run dev
```

### Everything with Docker

```bash
docker compose up --build        # API on :8000, console on :3000
```

### Policy tests

```bash
opa test policy/opa -v
```

Then follow the [3-minute demo](docs/demo-scenarios.md).

## API surface (all under `/api/v1`)

| Area | Endpoints |
|---|---|
| Agent runtime | `POST /runs` · `GET /runs/{id}` · `POST /runs/{id}/resume` · `GET/POST /agent-versions` · `POST /agent-versions/{id}/promote` |
| Policies | `GET /policies` · `POST /policies` (admin, atomic replace) · `POST /policies/validate` · `POST /policies/simulate` · `GET /policies/history` |
| Approvals | `GET /approvals?status=&approver_role=` · `GET /approvals/{id}` · `POST /approvals/{id}/decision` (approve, reject, `request_info`, `decided_by_role`) |
| Observability | `GET /traces` (filters) · `GET /traces/{id}` · `GET /observability/stats` · `GET /observability/metrics` (Prometheus) · `GET /budgets/{tenant}` |
| Evaluation | `GET /evaluations/datasets` · `POST /evaluations` · `GET /evaluations/{id}` · `POST /evaluations/compare` · `POST /redteam/run` |
| Multi-agent | `GET /orchestrations/agents` · `POST /orchestrations/run` |
| Enforcement core | `POST /decisions` · `POST /gateway/authorize` · `POST /tools/execute` · `POST /mcp/call` · `/agents` · `/security/*` · `/delegations/*` · `/anomaly/*` · `/control-plane/snapshot` · `/health` |

## Security model

1. **Identify first.** Unknown, suspended or revoked agents cannot execute tools.
2. **Least privilege.** The action must be in the agent's permission set; sub-agents get only what their job needs.
3. **Credential isolation.** Every run gets short-lived credentials scoped to one tool's actions.
4. **Server-side ownership.** Resource owner and tenant are resolved from the data, never taken from the prompt.
5. **Untrusted text is data.** Content from documents, tools, email and other agents is tracked and scored on every later call.
6. **Strictest decision wins.** Declarative rules can only tighten the baseline risk policy.
7. **Humans for high impact.** Approvals are role-routed, fingerprint-bound, expiring, single-use and re-checked on resume.
8. **Minimise what leaves.** Redaction for outbound payloads, plus an output guard on answers.
9. **Bounded spend.** Step, token and ₹ budgets per run and per tenant per day, and per-action rate limits.
10. **Evidence for everything.** A SHA-256 hash-chained audit with policy id, trace id and tenant; full traces; persisted when Supabase is configured.
11. **Fail closed.** Bad credentials, missing production auth, an invalid policy file or a planner/provider error all deny rather than degrade.
12. **No LLM in the enforcement path.** Authorization, inspection, scoring and policy are deterministic code.

Details: [docs/threat-model.md](docs/threat-model.md) maps threats to the OWASP LLM and Agentic Top 10.

## Production configuration

| Variable | Purpose |
|---|---|
| `AGENTGUARD_ENV` | `production` enables fail-closed authentication. |
| `AGENTGUARD_API_KEY` / `AGENTGUARD_OPERATORS` | Operator keys (`key:admin|reviewer|viewer`). Reviewers may decide approvals, resume runs and simulate policies. |
| `AGENTGUARD_POLICY_FILE` | YAML/JSON policy pack. If it fails validation, startup stops. |
| `AGENTGUARD_CORS_ORIGINS`, `AGENTGUARD_RATE_LIMIT`, `AGENTGUARD_RATE_LIMIT_WINDOW`, `AGENTGUARD_POLICY_VERSION` | API boundary settings. |
| `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` | Durable persistence (server-side only). Apply `supabase/migrations/*` first. |
| `SENTINELFORGE_LLM_API_KEY`, `SENTINELFORGE_LLM_BASE_URL`, `SENTINELFORGE_LLM_MODEL` | Enable the LLM-backed agent version on any OpenAI-compatible endpoint. |
| `SENTINELFORGE_CONSOLE_KEY` (console) | Dedicated server-side key for the console proxy. |

Install `.[otel]` and configure a standard OTLP exporter to ship spans to Jaeger, Tempo, Honeycomb or Datadog.
Scrape `/api/v1/observability/metrics` with Prometheus.

## CI

Every push runs the backend tests, checks that the datasets regenerate identically, runs three release gates
(v1.0 and v2.1 must pass, v2.0 must be blocked), uploads the evaluation evidence, runs the Rego parity tests,
builds the console and builds both Docker images.

## License

MIT
