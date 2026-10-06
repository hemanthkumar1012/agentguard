# AgentGuard Engineering Ledger

This ledger records small, reviewable engineering improvements made while hardening AgentGuard. Each entry corresponds to a real repository change and is intentionally kept separate so the history remains easy to audit.

## Improvements

- Establish a dedicated engineering ledger for security, reliability, testing, and documentation work.

- Document the backend API as the authoritative enforcement boundary.
- Document that browser tokens must remain short-lived and scoped.
- Document fail-closed behavior for unavailable policy enforcement.