# AgentGuard deployment

This repository is deployable as a two-service Render stack or as split hosting:

- **API:** Docker/FastAPI on Render (or any container platform).
- **Control plane:** Next.js on Render using the included frontend Dockerfile, or on Vercel/another Node.js host.
- **Persistence:** Supabase PostgreSQL.

For the simplest end-to-end deployment, use the included `render.yaml` for **both** the API and the control plane. The Blueprint wires the frontend to the API and copies the API credential server-to-server inside Render, so the browser never receives it.

The runtime does not require an AI/ML/LLM provider.

Configured MCP servers can be added with `AGENTGUARD_MCP_SERVERS` using
`name=https://host/mcp` entries and optional server-side bearer tokens in
`AGENTGUARD_MCP_TOKENS` using `name=token` entries. Remote calls are only registered
after AgentGuard authorization, use bounded request timeouts, and never expose the
configured token to the browser. HTTPS is required for non-localhost endpoints.

## 1. Apply the database migrations

Create a Supabase project and apply, in order:

```text
supabase/migrations/0001_agentguard_core.sql
supabase/migrations/0002_audit_integrity.sql
supabase/migrations/0003_approval_execution_gate.sql
```

Use the Supabase SQL editor or the Supabase CLI from your deployment environment. Do not run schema migrations from application startup; schema changes should be an explicit deployment step.

The API uses the server-side Supabase service key. Never expose that key to the browser.

The repository's `docker-compose.yml` is an API-container configuration, not a
raw-PostgreSQL replacement for Supabase. Supply `SUPABASE_URL` and
`SUPABASE_SERVICE_KEY` through the Compose environment. When those values are absent,
the API intentionally stays in zero-config in-memory development mode.

Requests that require approval return an `approval_id`. After an operator approves that
request, the caller must retry the identical request with that `approval_id`. The approval
is bound to the request fingerprint and is consumed after one successful authorization,
preventing approval replay or request substitution.

## 2. Deploy the complete stack on Render

The repository includes a two-service `render.yaml`:

```text
agentguard-api      → FastAPI/Docker → Supabase
agentguard-console  → Next.js/Docker → agentguard-api
```

Render automatically wires:

- `AGENTGUARD_BACKEND_URL` from the API service's `RENDER_EXTERNAL_URL`.
- `AGENTGUARD_API_KEY` into the frontend from the API service, without copying the secret into Git.
- `AGENTGUARD_CORS_ORIGINS` from the frontend service's `RENDER_EXTERNAL_URL`.

The Blueprint generates the API key once when the service is first created. Existing values are preserved on later syncs.

At first Blueprint sync, provide only these external secrets:

```text
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_KEY=<server-side-supabase-key>
```

Recommended runtime values are already declared in the Blueprint:

```text
AGENTGUARD_ENV=production
AGENTGUARD_POLICY_VERSION=2026.09
AGENTGUARD_RATE_LIMIT=120
AGENTGUARD_RATE_LIMIT_WINDOW=60
```

The API container binds to `$PORT`, runs as a non-root user, and exposes liveness and readiness checks:

```text
GET /api/v1/health
GET /api/v1/health/ready
```

The frontend health check is:

```text
GET /
```

## 3. Optional Vercel deployment

Vercel can still host the control plane separately if desired. Set the project Root Directory to `frontend` and provide these server-only variables:

```text
AGENTGUARD_BACKEND_URL=https://<your-api-domain>
AGENTGUARD_API_KEY=<the-same-api-key-used-by-the-api>
```

Do **not** use `NEXT_PUBLIC_AGENTGUARD_API_KEY`. The browser must never receive the API credential.

The dashboard calls `/api/control-plane/snapshot`; the Next.js server route forwards that request to the protected API and injects the API key server-side.

## 4. CORS and browser access

The dashboard uses a server-side proxy, so the API credential is not exposed to browser JavaScript. Keep `AGENTGUARD_CORS_ORIGINS` restricted to the frontend origin that needs direct API access.

The Render Blueprint automatically sets it to the exact frontend `onrender.com` URL. For a separate Vercel deployment, replace it with the exact HTTPS Vercel origin.

Do not use `*` in production.

## 5. Deployment verification

After deployment:

1. Open the API `/api/v1/health` and confirm HTTP 200.
2. Open the API `/api/v1/health/ready` and confirm `status=ready` and all production checks are `ok`.
3. Open the frontend and confirm `API connected` is displayed.
4. Execute an authorized tool request and confirm it appears in the forensic stream.
5. Verify an unauthorized request returns `401` or `403` as appropriate.
6. Verify an invalid credential cannot execute a tool.
7. Verify approval is bound to the exact request and cannot be replayed.
8. Verify audit integrity remains valid after a restart.
9. Confirm the frontend deployment does not contain `AGENTGUARD_API_KEY` in client-side JavaScript.

## 6. Important scaling boundary

The current enforcement runtime keeps the rate limiter and active audit-chain state in process memory while persisting authoritative records in Supabase. Deploy the API as a single instance until a distributed rate limiter and concurrency-safe event sequencing layer are introduced.

For horizontal scaling, add a shared rate-limit store (for example Redis) and a database-backed serialization strategy for audit event appends before increasing API replicas.

## 7. Local production-like container check

Build and run the API container with production configuration supplied through the environment:

```bash
docker build -t agentguard-api .
docker run --rm -p 8000:8000 --env-file backend/.env agentguard-api
```

Then check:

```text
http://localhost:8000/api/v1/health
```

The frontend Dockerfile can be tested similarly from `frontend/`:

```bash
docker build -t agentguard-console ./frontend
docker run --rm -p 3000:3000 \
  -e AGENTGUARD_BACKEND_URL=https://<api-domain> \
  -e AGENTGUARD_API_KEY=<api-key> \
  agentguard-console
```

Do not commit local env files or any production secrets.
