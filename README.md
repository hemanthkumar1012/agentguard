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
  the **lethal trifecta** while letting normal work (replying to a customer with their own order) through;
- it adds up pieces of secrets sent over several requests, and checks the URLs in a model's reply before a
  client renders them (EchoLeak leaked through a rendered image, not a tool call);
- labels are shared through Redis with compare-and-set, and every failure path blocks.

Labels are never taken from the agent. Before this design, the agent sent its own `risk_score` and
`data_classification`. An agent that had read a customer record could declare "public, risk 0" and
export it ([findings log](docs/findings-log.md)).

## Results

From [`docs/benchmarks.md`](docs/benchmarks.md), regenerated with `make bench`; the traces also run in CI.

| | Before | After |
|---|---|---|
| Reconstructed published attacks stopped (GitHub MCP toxic flow, Supabase MCP token leak, two EchoLeak paths) | 0 / 4 | 4 / 4 |
| All attack traces stopped (adds memory recall, paraphrase, self-declared labels, secrets in pieces) | 6 / 10 * | 9 / 10 |
| Benign traces needing approval or blocked | 5 / 9 | 3 / 9 (two intended approvals, one known false block) |
| Secret detector on the labelled corpus: recall / false-positive rate | 0.082 / 0.452 | 1.000 / 0.000 † |
| Decision latency p50, 1 KB / 10 KB outbound body (all rules, 20 secrets tracked) | 0.11 / 0.45 ms | 0.92 / 4.1 ms |

\* The old engine "stopped" those six only because it asked for approval on every request containing an
email address. † Synthetic corpus written alongside the detectors: useful for comparing versions, not a
real-world accuracy claim. The 50 known-gap cases are reported separately (0 caught).

Known gaps, shown in the benchmark rather than hidden: a secret sent 3 characters at a time from a clean
session gets through, and a session that reads two customers' records can no longer reply to either
(label creep).

## How it is tested

- **Model-based fuzzing** of the flow rules: random worlds and traces checked after every step by an
  independent oracle (no allowed leak, labels only grow, declared risk never matters, …). 70,000 random
  steps, no violations. The fuzzer was itself mutation-tested: it first caught 4 of 6 planted bugs, its
  generator was fixed, now 6 of 6.
- **Trace replays** of published attacks and ordinary work, gated in CI, with each layer switched on in turn
  so every rule's contribution is visible.
- **Concurrency tests**: several audit writers from 9 threads must keep one linear chain; 8 threads tainting
  one session through real Redis must lose nothing (the test fails if the compare-and-set is removed).
- **Policy parity**: the Rego and Python policies must agree over a grid of requests.
- **Labelled corpus** for the secret detector, with a CI gate on recall and false-positive rate.

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
| F5 | more than half of a secret's pieces have reached one destination domain, over any number of requests | block if untrusted, else approval |
| O1 | a URL in a model reply could leak (`POST /flow/check-output`, called before rendering) | URL neutralised |

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
- **Several workers:** labels in Redis with compare-and-set and expiry that blocks; the audit chain stays
  linear through a database-enforced sequence number. If the label store fails, requests are blocked, an
  allow whose taint cannot be recorded is withdrawn, and tool output that cannot be labelled is withheld.

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
| Flow | `POST /flow/check-output` | Neutralise leaking URLs in a model reply before rendering |
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
- `AGENTGUARD_FLOW_REDIS_URL`: share session labels between workers (e.g. `redis://localhost:6379/0`);
  without it labels live in process memory. `AGENTGUARD_FLOW_SESSION_TTL`: operator session lifetime in
  seconds (default 86400); an expired session is blocked.
- `AGENTGUARD_OPA_URL`: optional OPA server; unreachable means blocked.
- `AGENTGUARD_CORS_ORIGINS`, `AGENTGUARD_RATE_LIMIT`, `AGENTGUARD_RATE_LIMIT_WINDOW`, `AGENTGUARD_POLICY_VERSION`.
- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`: server-side only.

## Limitations

Listed with proposed fixes in [`docs/findings-log.md`](docs/findings-log.md#open-issues). The main ones:
the agent still holds raw API keys (the gateway should inject them); fingerprints and secret pieces are
indexed per worker; if Redis loses data, default labels come back clean.

## Repository layout

```text
backend/
  app/flow/        labels, session stores (memory, Redis), fingerprints, secret pieces, output check, rules
  app/             gateway, policy, inspector, credentials, approvals, audit, API
  benchmarks/      attack/benign traces, labelled corpus, latency, report generator
  tests/           unit, API, fuzzing, concurrency, Redis, trace-replay and policy-parity tests
policy/opa/        Rego policy + tests
supabase/          migrations (RLS, audit integrity columns)
docs/              decisions (ADRs), findings log, benchmarks, flow-control guide
frontend/          Next.js console
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and `make help`.

## License

MIT
