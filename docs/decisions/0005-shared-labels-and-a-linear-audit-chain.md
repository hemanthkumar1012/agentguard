# 0005. Shared labels and a linear audit chain under several workers

Date: 2026-11-27. Status: accepted.

## Context

Two pieces of state were kept in each process's memory:

- **Session labels.** A second worker, or the same worker after a restart, saw an unknown or clean label
  for a session that had already read private data and untrusted content. The flow rules failed open.
- **The head of the audit chain.** Each worker chained new events from its own last event. With two
  workers the chain forked on the first pair of writes, even without concurrency, and a restarted worker
  reported the audit trail as tampered.

Both are the same problem: several writers updating one piece of shared state.

## Decision

Optimistic concurrency (compare-and-swap) in both places, and fail closed on every error.

**Labels in Redis** (`AGENTGUARD_FLOW_REDIS_URL`):

- one hash per session: `version` and `doc` (the label as JSON);
- a change is read → apply the same `apply_*` functions the memory store uses → write with a Lua script
  that succeeds only if `version` is unchanged; otherwise re-read and retry, with jittered exponential
  backoff (without it, 8 writers on one session starved a writer after 16 attempts);
- operator sessions expire after `AGENTGUARD_FLOW_SESSION_TTL`. An expired session no longer resolves, so
  it is blocked (F0), never treated as clean;
- a Redis error while reading a label blocks the request; failing to record a taint after an allow
  withdraws the allow; tool output that cannot be labelled is withheld from the agent (HTTP 503).

**Audit chain:** each event carries the next sequence number, and the store keeps it unique (a unique
index in Postgres, migration 0004). The writer that loses the race loads the events it missed and retries
on top of them. After 8 losses the append fails, and so does the request. The sequence is not part of the
hash, so rows written before it existed still verify, and the chain is ordered by sequence, not
`created_at`, because worker clocks disagree.

## Alternatives considered

- **Sticky sessions (route a session to one worker).** Does not survive restarts or scale-downs, and the
  default session is shared by every request of an agent.
- **A Redis lock around each label update.** Correct, but a crashed holder blocks the session until the
  lock times out. Compare-and-set needs no lock and loses nothing when a writer dies mid-way.
- **Lua that applies the whole label change inside Redis.** Atomic in one round trip, but the label logic
  would exist twice (Python and Lua). Keeping the logic in Python and using Redis only for an atomic
  version check keeps one source of truth.
- **A single audit writer process.** Simple, but a single point of failure in front of every decision.

## Consequences

- Labels are consistent across workers and restarts; the race test fails if the version check is
  removed, so it guards the compare-and-set itself.
- Fingerprints and secret pieces are still per process (see the open issues in `docs/findings-log.md`).
- If Redis loses data, default labels come back clean: run Redis with persistence.
