# AgentGuard

[![Backend CI](https://github.com/hemanthkumar1012/agentguard/actions/workflows/backend-ci.yml/badge.svg)](https://github.com/hemanthkumar1012/agentguard/actions/workflows/backend-ci.yml)
[![Frontend CI](https://github.com/hemanthkumar1012/agentguard/actions/workflows/frontend-ci.yml/badge.svg)](https://github.com/hemanthkumar1012/agentguard/actions/workflows/frontend-ci.yml)

**A runtime firewall between AI agents and their tools that tracks where data came from and where it is going.**

Prompt injection cannot be reliably detected in the text: the published agent leaks of 2025 (GitHub MCP,
Supabase MCP, EchoLeak) all came from an agent that read attacker-written text, then private data, and
then sent data out. AgentGuard does not try to spot the injection. It tracks the **flow**:

- it labels each agent session from what the tools AgentGuard runs actually return: "has read untrusted
  content", "has read private data that only these people may read";
- it fingerprints private tool output (winnowing, the algorithm behind MOSS), so the same data is
  recognised later, even reformatted, base64-encoded or sent from another session;
- before any outbound call it checks the destination's audience against the data's readers, and blocks
  the **lethal trifecta** while letting normal work (replying to a customer with their own order) through.

Labels are never taken from the agent. Before this design, the agent sent its own `risk_score` and
`data_classification`. An agent that had read a customer record could declare "public, risk 0" and
export it ([findings log](docs/findings-log.md)).

## Results

From [`docs/benchmarks.md`](docs/benchmarks.md), regenerated with `make bench`; the traces also run in CI.

| | Before | After |
|---|---|---|
| Published attacks stopped (GitHub MCP toxic flow, Supabase MCP token leak, EchoLeak-style URL exfiltration) | 0 / 3 | 3 / 3 |
| All attack traces stopped (adds memory recall into a new session, paraphrase, self-declared labels, split secret) | 4 / 7 * | 6 / 7 |
| Benign traces needing approval or blocked | 5 / 7 | 2 / 7 (one intended approval, one known false block) |
| Secret detector on the labelled corpus: recall / false-positive rate | 0.082 / 0.452 | 1.000 / 0.000 † |
| Decision latency p50, 1 KB / 10 KB outbound body | 0.11 / 0.45 ms | 0.68 / 3.4 ms |

\* The old engine "stopped" those four only because it asked for approval on every request containing an
email address. † Synthetic corpus written alongside the detectors: useful for comparing versions, not a
real-world accuracy claim. The 50 known-gap cases are reported separately (0 caught).

Known gaps, shown in the benchmark rather than hidden: a secret sent in pieces under 15 characters from a
clean session gets through, and a session that reads two customers' records can no longer reply to either
(label creep).

## How a decision is made

```
identity → permission → session → scoped credential → content inspection + risk → policy (Python or OPA)
        → data-flow rules (can only tighten) → human approval → hash-chained audit → label update
```

| Rule | When | Decision |
|---|---|---|
| F0 | session unknown, closed or another agent's | block |
| F1 | session read untrusted content **and** private data, destination audience outside the data's readers | block |
| F2 | private data, no untrusted content, destination outside readers | human approval |
| F3 | fingerprints of earlier private output found in the request, destination outside its readers | block if untrusted, else approval |
| F4 | untrusted content + high-impact state change (payment, delete) | human approval |

Why each rule and severity, and what was rejected: [`docs/decisions/`](docs/decisions). Setup:
[`docs/flow-control.md`](docs/flow-control.md).

## Also in the box

- **Agent identity:** register, suspend, revoke; unknown or inactive agents cannot act.
- **Scoped credentials:** short-lived, opaque, bound to agent + tool + action; only a hash is persisted.
- **Outbound inspection:** provider key formats (AWS, GitHub, Google, Slack, Stripe), JWTs, private keys,
  connection strings, card numbers (Luhn + network prefix), Aadhaar (Verhoeff checksum) and PAN, entropy
  with a word-likeness check, and bounded base64/hex/URL decoding. Only high-severity findings force approval.
- **Human approvals:** bound to a fingerprint of the exact request, single use, expiring.
- **Audit trail:** SHA-256 hash chain, restored from Postgres/Supabase when configured.
- **Policy as code:** the Rego policy and the Python policy are kept in parity by a test that compares
  their decisions over a grid of requests (it found a real gap at risk 60–69).
- **Hardening:** operator roles (admin/reviewer/viewer), constant-time key comparison, fail-closed
  production auth, rate limiting, security headers, OPA fail-closed when unreachable.
- **Rollout:** `AGENTGUARD_FLOW_MODE=monitor` records what the flow rules *would* do without changing
  decisions.

Smaller pieces are deliberately simple: the anomaly module is a z-score on a caller-supplied call rate and
is not part of the decision path.

## Run locally

```bash
cd backend
python -m pip install -e ".[test]"
uvicorn app.main:app --reload --port 8000     # API docs at http://localhost:8000/docs
python -m pytest -q                            # tests
python -m benchmarks.run                       # benchmark report
```

```bash
cd frontend && npm install && npm run dev      # console; set NEXT_PUBLIC_API_URL if not localhost:8000/api/v1
```

`docker compose up --build` starts the API and passes `SUPABASE_URL` / `SUPABASE_SERVICE_KEY` through.
Apply the migrations in `supabase/migrations/` before setting `AGENTGUARD_ENV=production`.

## API surface (`/api/v1`)

| Area | Endpoint | Purpose |
|---|---|---|
| Health | `GET /health`, `GET /health/ready` | Liveness; dependency and audit-integrity readiness |
| Agents | `POST /agents`, `GET /agents`, `POST /agents/{id}/suspend`, `POST /agents/{id}/revoke` | Identity lifecycle |
| Decisions | `POST /decisions`, `POST /gateway/authorize` | Authorization without execution |
| Tools | `POST /tools/execute`, `POST /mcp/call` | Authorize, execute, label the output |
| Flow | `POST /flow/sessions`, `GET /flow/sessions/{id}`, `POST /flow/sessions/{id}/close` | Session labels |
| Flow | `GET/POST /flow/manifests`, `GET/POST /flow/destinations`, `GET /flow/status` | Tool capabilities, destination audiences |
| Security | `POST /security/inspect`, `POST /security/risk`, `POST /security/credentials`, `POST /security/credentials/{id}/revoke` | Inspection, risk, credentials |
| Approvals | `/approvals/*` | Human approval workflow |
| Delegation | `/delegations/*` | Agent-to-agent scopes |
| Audit | `GET /gateway/audit` | Hash-chained event stream |
| Simulator | `/simulator/*` | Synthetic attack scenarios |
| Control plane | `GET /control-plane/snapshot` | Dashboard metrics |

## Configuration

- `AGENTGUARD_ENV`: `production` turns on fail-closed authentication.
- `AGENTGUARD_API_KEY` / `AGENTGUARD_OPERATORS` (`key:admin|reviewer|viewer,…`): operator credentials.
  Flow sessions, manifests and destinations need `admin`.
- `AGENTGUARD_FLOW_MODE`: `enforce` (default), `monitor` or `off`.
- `AGENTGUARD_OPA_URL`: optional OPA server; unreachable means blocked.
- `AGENTGUARD_CORS_ORIGINS`, `AGENTGUARD_RATE_LIMIT`, `AGENTGUARD_RATE_LIMIT_WINDOW`, `AGENTGUARD_POLICY_VERSION`.
- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`: server-side only.

## Limitations

Listed with proposed fixes in [`docs/findings-log.md`](docs/findings-log.md#open-issues). The main ones:
session labels live in process memory (production needs Redis, failing closed when a label is missing);
the audit chain can fork with several workers; AgentGuard sees tool calls, not what a chat client renders.

## Repository layout

```text
backend/
  app/flow/        labels, session store, winnowing fingerprints, flow rules, engine
  app/             gateway, policy, inspector, credentials, approvals, audit, API
  benchmarks/      attack/benign traces, labelled corpus, latency, report generator
  tests/           unit, API, trace-replay and policy-parity tests
policy/opa/        Rego policy + tests
supabase/          migrations (RLS, audit integrity columns)
docs/              decisions (ADRs), findings log, benchmarks, flow-control guide
frontend/          Next.js console
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and `make help`.

## License

MIT
