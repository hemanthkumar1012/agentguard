# AgentGuard Engineering Ledger

This ledger records small, reviewable engineering improvements made while hardening AgentGuard. Each entry corresponds to a real repository change and is intentionally kept separate so the history remains easy to audit.

## Improvements

- Establish a dedicated engineering ledger for security, reliability, testing, and documentation work.

- Document the backend API as the authoritative enforcement boundary.
- Document that browser tokens must remain short-lived and scoped.
- Document fail-closed behavior for unavailable policy enforcement.
- Document audit events as security evidence rather than UI telemetry.
- Document approval fingerprints as exact-request authorization.
- Define agent identity as a prerequisite for every protected action.
- Keep authorization decisions independent from presentation-layer UI state.
- Treat policy evaluation as deterministic and reproducible.
- Keep high-impact actions explicit instead of inferred from UI labels.
- Record risk factors alongside the final risk score for operator review.
- Preserve request IDs across gateway, audit, and API responses.
- Keep sensitive-data classifications separate from action risk.
- Require approval only when policy semantics explicitly demand it.
- Ensure approval records have an expiration boundary.
- Prevent an approval from silently authorizing a different request.
- Keep credential scope narrower than agent identity scope.
- Never place permanent operator API keys in browser code.
- Keep Supabase service credentials server-side.
- Use environment variables for deployment-specific backend configuration.
- Document production and preview environment differences.
- Keep health endpoints lightweight and safe to expose.
- Rate-limit browser security endpoints independently from general API traffic.