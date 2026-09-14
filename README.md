# AgentGuard

**Runtime Security & Control Plane for AI Agents**

AgentGuard is a deterministic security enforcement layer for agentic systems. It answers a runtime security question that static RBAC cannot answer reliably:

> Should this particular agent be allowed to perform this particular action, with this particular data, against this particular target, right now?

It sits between agents and the tools/APIs they can execute, combining identity, least privilege, contextual risk, data inspection, scoped credentials, MCP controls, approvals, anomaly detection, delegation, and tamper-evident audit events.

## What is implemented

- **Agent identity:** register, inspect, suspend, revoke, and list agents.
- **Runtime authorization:** all decision requests pass through the same gateway enforcement path used by tool execution.
- **Risk engine:** sensitive-data, high-impact-action, external-target, and transport-risk factors.
- **Data inspection:** detects common email, API-key, card-number, and secret markers before execution.
- **Credential broker:** opaque, short-lived, agent/tool/scope-bound credentials; issuance is denied outside the agent's permissions.
- **Tool gateway:** one enforcement point before tool execution.
- **MCP boundary:** tool calls pass through AgentGuard authorization before the runtime executes them.
- **Human approvals:** pending/approved/denied/expired approval lifecycle.
- **Agent-to-agent delegation:** explicit source/target/action scopes.
- **Behavior anomaly baseline:** deterministic, explainable rate-based anomaly scoring; no model or external AI service is required at runtime.
- **Attack simulator:** deterministic synthetic attack scenarios for security demos and regression testing.
- **Control-plane dashboard API:** agent posture, decision counts, risk statistics, and recent events.
- **Forensic audit events:** policy version, correlation ID, tool, credential, risk factors, data findings, and a SHA-256 hash chain.
- **Production hardening:** CORS allowlist, constant-time API-key comparison, request IDs, security headers, no-store responses, and fail-closed production authentication.
- **Durable persistence contract:** PostgreSQL/Supabase migration with RLS, indexes, and audit integrity columns.
- **OPA policy:** Rego policy and regression tests kept in parity with the deterministic Python policy engine.
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
| Health | `GET /health/ready` | Dependency and audit-integrity readiness |
| Agents | `POST /agents` | Register identity |
| Agents | `GET /agents` | List identities |
| Agents | `POST /agents/{id}/suspend` | Suspend identity |
| Agents | `POST /agents/{id}/revoke` | Revoke identity |
| Decisions | `POST /decisions` | Enforced runtime authorization decision |
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
6. **Fail closed.** Invalid identity, permission, credential, and missing production API authentication result in denial rather than an unsafe fallback.
7. **Audit everything.** Decisions carry correlation, policy, tool, credential, risk, and data-inspection metadata.
8. **Tamper evidence.** Each in-memory audit event is SHA-256 chained to the preceding event; the chain can be integrity-checked through the runtime ledger.
9. **No AI dependency in the enforcement path.** Runtime authorization, inspection, risk scoring, anomaly detection, and policy evaluation are deterministic application logic.
10. **Defense in depth.** PostgreSQL/Supabase RLS protects the durable data boundary when persistence is configured.

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

The Compose stack starts FastAPI and PostgreSQL. Migrations are applied by PostgreSQL initialization for a clean local database.

## Production configuration

Environment variables:

- `AGENTGUARD_ENV` — deployment environment. Set to `production` for production deployments.
- `AGENTGUARD_CORS_ORIGINS` — comma-separated frontend origins; do not use `*` with credentialed browser access.
- `AGENTGUARD_API_KEY` — API boundary key. It is required for protected routes in production and supports `X-API-Key` or `Authorization: Bearer ...`.
- `AGENTGUARD_POLICY_VERSION` — policy version stamped into audit events.
- `SUPABASE_URL` — server-side Supabase project URL.
- `SUPABASE_SERVICE_KEY` — server-side secret key; never expose it to the frontend or commit it to source control.

Never put real provider tokens into source control. The credential broker returns an opaque token only at issuance and stores demo credentials in memory; the production schema stores only a token hash.

## Verification

The backend test suite covers the core security invariants, including:

- unknown/suspended agents
- least-privilege credential issuance
- runtime decision enforcement
- approval lifecycle
- API-key authentication and CORS preflight
- production fail-closed behavior
- tamper-evident audit chaining

CI must be green before considering a change complete.

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

## Production hardening still required outside the demo runtime

The repository now has a complete deterministic security-control-plane demonstrator. A real production deployment would still need environment-specific operational integrations rather than new security logic: durable repositories for agent/credential/approval state, authenticated operator sessions with Supabase Auth/RLS policies, distributed event transport such as Redis Streams if required by scale, OpenTelemetry/Prometheus integration, external KMS/HSM-backed provider credentials, deployment-specific secret management, and infrastructure-level rate limiting.

These integrations are intentionally kept outside the deterministic enforcement logic. No external AI/ML/LLM service is required for AgentGuard to make an authorization decision.

## License

MIT
