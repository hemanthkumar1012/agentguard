# AgentGuard

Runtime security and authorization for AI agents.

AgentGuard is a security control plane for agentic systems. It evaluates whether an agent should be allowed to perform a requested action with specific data, tools, credentials, and targets under the current context.

## Why AgentGuard

AI agents are increasingly capable of planning and executing actions across APIs, databases, files, browsers, and other agents. Traditional static RBAC does not answer an important runtime question:

> Should this particular agent be allowed to perform this particular action, with this particular data, against this particular target, right now?

AgentGuard is designed around that decision.

## Core capabilities

- Agent identity and trust
- Context-aware authorization decisions
- Policy enforcement at the tool/API boundary
- Risk scoring and decision explanations
- Short-lived, scoped credential brokering
- Prompt/tool attack detection
- Behavioral anomaly detection
- Agent-to-agent authorization
- MCP/tool security controls
- Audit events and forensic replay
- Blast-radius analysis
- Human approval workflows
- Red-team attack simulation

## Architecture

```text
                         ┌──────────────────────┐
                         │       AI Agent        │
                         └──────────┬───────────┘
                                    │ action request
                                    ▼
                         ┌──────────────────────┐
                         │    Agent Identity    │
                         └──────────┬───────────┘
                                    ▼
                         ┌──────────────────────┐
                         │  Intent / Data Scan  │
                         └──────────┬───────────┘
                                    ▼
                         ┌──────────────────────┐
                         │    Policy Engine     │
                         └──────────┬───────────┘
                                    ▼
                         ┌──────────────────────┐
                         │      Risk Engine     │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
                 ALLOW        HUMAN APPROVAL       BLOCK
                    │               │
                    └───────┬───────┘
                            ▼
                  ┌──────────────────────┐
                  │ Credential Broker    │
                  └──────────┬───────────┘
                             ▼
                  ┌──────────────────────┐
                  │ Tool / API Gateway   │
                  └──────────┬───────────┘
                             ▼
                       External tool
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Audit + Observability│
                  └──────────────────────┘
```

## Planned stack

### Frontend
- Next.js
- TypeScript
- Tailwind CSS

### Backend
- Python
- FastAPI
- Pydantic
- SQLAlchemy

### Data and infrastructure
- PostgreSQL
- Supabase
- pgvector
- Redis
- Docker

### Security and policy
- Open Policy Agent (OPA)
- MCP security gateway patterns
- Short-lived scoped credentials

### AI / ML
- LLM-based intent and risk analysis
- scikit-learn anomaly detection
- Embedding-based behavioral similarity

### Observability
- OpenTelemetry
- Prometheus
- Grafana

### Delivery
- GitHub Actions
- Vercel for frontend
- Containerized backend deployment

## Repository layout

```text
agentguard/
├── frontend/
├── backend/
├── ml/
├── policy/
├── mcp/
├── infrastructure/
├── tests/
├── .github/
├── .devcontainer/
├── docker-compose.yml
└── README.md
```

## Development philosophy

AgentGuard should demonstrate production engineering rather than a tutorial CRUD application.

The implementation will prioritize:

1. Explicit security boundaries
2. Deterministic policy decisions where possible
3. Explainable risk decisions
4. Least-privilege credentials
5. Complete auditability
6. Automated tests and attack simulations
7. Observable runtime behavior
8. Safe failure modes

## Status

Early foundation. The initial milestone establishes the backend service, security domain model, policy decision endpoint, health checks, tests, and developer tooling.

## License

MIT
