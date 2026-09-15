# AgentGuard deployment

This repository is deployable as two services:

- **API:** Docker/FastAPI on Render (or any container platform).
- **Control plane:** Next.js on Vercel (or any Node.js host).
- **Persistence:** Supabase PostgreSQL.

The runtime does not require an AI/ML/LLM provider.

## 1. Apply the database migrations

Create a Supabase project and apply, in order:

```text
supabase/migrations/0001_agentguard_core.sql
supabase/migrations/0002_audit_integrity.sql
```

Use the Supabase SQL editor or the Supabase CLI from your deployment environment. Do not run schema migrations from application startup; schema changes should be an explicit deployment step.

The API uses the server-side Supabase service key. Never expose that key to the browser.

## 2. Deploy the API

The repository includes `render.yaml` for Render.

Required production secrets:

```text
AGENTGUARD_API_KEY=<long-random-secret>
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_KEY=<server-side-supabase-key>
AGENTGUARD_CORS_ORIGINS=https://<your-frontend-domain>
```

Recommended runtime values:

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

Production readiness fails closed when persistence or API authentication is not configured, or when the audit chain is invalid.

## 3. Deploy the Next.js control plane

Create a Vercel project from this repository and set its **Root Directory** to `frontend`.

The frontend requires these server-side environment variables:

```text
AGENTGUARD_BACKEND_URL=https://<your-api-domain>
AGENTGUARD_API_KEY=<the-same-api-key-used-by-the-api>
```

Do **not** use `NEXT_PUBLIC_AGENTGUARD_API_KEY`. The browser must never receive the API credential.

The dashboard calls `/api/control-plane/snapshot`; the Next.js server route forwards that request to the protected API and injects the API key server-side.

## 4. CORS and browser access

Because the dashboard uses the server-side proxy, the API does not need to expose its API key to browsers. Keep `AGENTGUARD_CORS_ORIGINS` restricted to trusted origins that need direct API access.

For a single Vercel deployment, use its exact HTTPS origin, for example:

```text
https://agentguard.example.com
```

Do not use `*` in production.

## 5. Deployment verification

After deployment:

1. Open `/api/v1/health` on the API and confirm HTTP 200.
2. Open `/api/v1/health/ready` and confirm `status=ready` and all production checks are `ok`.
3. Open the frontend and confirm `API connected` is displayed.
4. Execute an authorized tool request and confirm it appears in the forensic stream.
5. Verify an unauthorized request returns `401` or `403` as appropriate.
6. Verify an invalid credential cannot execute a tool.
7. Verify audit integrity remains valid after a restart.
8. Confirm the frontend deployment does not contain `AGENTGUARD_API_KEY` in client-side JavaScript.

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

Do not commit `backend/.env` or any production secrets.
