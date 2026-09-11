# AgentGuard

**Runtime Security & Control Plane for AI Agents**

AgentGuard is a security enforcement layer for agentic systems. It answers a runtime security question that static RBAC cannot answer reliably:

> Should this particular agent be allowed to perform this particular action, with this particular data, against this particular target, right now?

It sits between agents and the tools/APIs they can execute, combining identity, least privilege, contextual risk, data inspection, scoped credentials, MCP controls, approvals, anomaly detection, delegation, and an immutable-style audit event contract.

## What is implemented

- **Agent identity:** register, inspect, suspend, revoke, and list agents.
- **Runtime authorization:** permission checks plus contextual risk evaluation at the gateway.
- **Risk engine:** sensitive-data, high-impact-action, external-target, and transport-risk factors.
- **Data inspection:** detects common email, API-key, card-number, and secret markers before execution.
- **Credential broker:** opaque, short-lived, agent/tool/scope-bound credentials; issuance is denied outside the agent's permissions.
- **Tool gateway:** one enforcement point before tool execution.
- **MCP boundary:** tool calls pass through AgentGuard authorization before the runtime executes them.
- **Human approvals:** pending/approved/denied/expired approval lifecycle.
- **Agent-to-agent delegation:** explicit source/target/action scopes.
- **Behavior anomaly baseline:** explainable rate-based anomaly scoring with a contract ready for an ML model.
- **Attack simulator:** deterministic synthetic attack scenarios for security demos and regression testing.
- **Control-plane dashboard API:** agent posture, decision counts, risk statistics, and recent events.
- **Forensic audit events:** policy version, correlation ID, tool, credential, risk factors, and data findings.
- **Production hardening:** CORS allowlist, optional API-key boundary, request IDs, security headers, no-store responses.
- **Durable persistence contract:** PostgreSQL/Supabase migration with RLS and indexes.
- **OPA policy:** Rego policy and regression tests are included alongside the Python policy engine.
- **CI:** backend tests and frontend production builds run on every push/PR to `main`.

## Architecture

```text
 AI Agent / MCP Client
          |
          v
 +-----------------------+
 | Agent Identity        |---- status / permissions / delegation
 +-----------+-----------+
             |
             v
 +-----------------------+
 | Data + Content Scan   |---- PII / secrets / exfil indicators
 +-----------+-----------+
             |
             v
 +-----------------------+
 | Risk Engine           |---- contextual score + factors
 +-----------+-----------+
             |
             v
 +-----------------------+
 | Policy / OPA Boundary |---- ALLOW / APPROVAL / BLOCK
 +------+-----------+----+
        |           |
   approval      blocked
        |           |
        v           v
 +-------------+  Audit Event
 | Human Gate  |      |
 +------+------+      |
        |             |
        +------v------+
        | Credential  |---- short-lived, scoped token
        | Broker      |
        +------+------+ 
               |
               v
        +-------------+
        | Tool / MCP  |
        | Gateway     |
        +------+------+ 
               |
               v
        External APIs / Tools
               |
               v
       Audit + Observability
```

## API surface

All APIs are under `/api/v1`.

| Area | Endpoint | Purpose |
|---|---|---|
| Health | `GET /health` | Liveness |
| Health | `GET /health/ready` | Readiness |
| Agents | `POST /agents` | Register identity |
| Agents | `GET /agents` | List identities |
| Agents | `POST /agents/{id}/suspend` | Suspend identity |
| Agents | `POST /agents/{id}/revoke` | Revoke identity |
| Decisions | `POST /decisions` | Policy decision + audit |
| Gateway | `POST /gateway/authorize` | Enforce runtime authorization |
| Gateway | `GET /gateway/audit` | Audit stream |
| Tools | `POST /tools/execute` | Authorized tool execution |
| MCP | `POST /mcp/call` | Authorized MCP tool call |
| Security | `POST /security/risk` | Contextual risk assessment |
| Security | `POST /security/inspect` | Data/secret inspection |
| Security | `POST /security/credentials` | Issue scoped credential |
| Security | `POST /security/credentials/{id}/revoke` | Revoke credential |
| Approvals | `/approvals/*` | Human approval workflow |
| Delegation | `/delegations/*` | Agent-to-agent authorization |
| Anomaly | `/anomaly/*` | Behavior baseline scoring |
| Simulator | `/simulator/*` | Synthetic attack scenarios |
| Control plane | `GET /control-plane/snapshot` | Dashboard metrics |

Interactive API documentation is available at `/docs` when the API is running.

## Security model

1. **Identify first.** Unknown, suspended, or revoked agents cannot execute tools.
2. **Least privilege.** The requested action must exist in the agent permission set.
3. **Credential isolation.** Tool execution requires a credential bound to the same agent, tool, and action scope.
4. **Inspect content.** Sensitive content increases runtime risk and is retained as findings, not as raw secrets in the audit contract.
5. **Evaluate context.** Risk factors change the effective score before the policy decision.
6. **Fail closed.** Invalid identity, permission, or credential results in `block`.
7. **Audit everything.** Decisions carry correlation, policy, tool, credential, risk, and data-inspection metadata.
8. **Separate demo from production.** The default runtime is dependency-light and in-memory; the included PostgreSQL schema is the persistence boundary for deployment hardening.

## Run locally

### Backend

```bash
cd backend
python -m pip install -e ".[test]"
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `NEXT_PUBLIC_API_URL` to the API base URL if it is not `http://localhost:8000/api/v1`.

### Full local infrastructure

```bash
docker compose up --build
```

The Compose stack starts FastAPI and PostgreSQL. The initial schema is mounted into PostgreSQL's initialization directory for a clean local database.

## Production configuration

Environment variables:

- `AGENTGUARD_ENV` — deployment environment.
- `AGENTGUARD_CORS_ORIGINS` — comma-separated frontend origins.
- `AGENTGUARD_API_KEY` — optional API boundary key. When set, non-health API routes require `X-API-Key` or `Authorization: Bearer ...`.
- `AGENTGUARD_POLICY_VERSION` — policy version stamped into audit events.

Never put real provider tokens into source control. The credential broker stores opaque demo credentials in memory; the production schema stores only a token hash.

## Repository layout

```text
agentguard/
├── frontend/                 # Next.js security console
├── backend/
│   ├── app/                  # FastAPI control plane + enforcement
│   └── tests/                # security and API regression tests
├── policy/opa/               # Rego policy + tests
├── supabase/migrations/      # durable PostgreSQL/Supabase schema
├── .github/workflows/        # backend + frontend CI
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Engineering roadmap

The core demonstrator is now implemented. The next production-grade integrations are intentionally isolated behind the current contracts:

1. Replace the in-memory ledgers/registries with PostgreSQL/Supabase repositories.
2. Add Supabase Auth and authenticated operator/RLS policies.
3. Connect Redis Streams for high-volume event ingestion.
4. Add OpenTelemetry/Prometheus metrics and distributed tracing.
5. Replace the baseline anomaly detector with a trained scikit-learn model and model-version metadata.
6. Add real provider adapters for OpenAI/Anthropic/local agents while keeping AgentGuard provider-neutral.
7. Add signed event integrity/chaining for tamper-evident forensic storage.
8. Add deployment manifests, secret management, rate limiting, and external KMS-backed credentials.

These are deployment integrations rather than prerequisites for the security-control-plane demonstration already in the repository.

## License

MIT
