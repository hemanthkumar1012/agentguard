# 0007. Credential injection, and how the system is shown to work

Date: 2026-11-27. Status: accepted.

## Context

After rounds one and two, the biggest open issue was that agents held raw API keys. A key read from a vault
tool sat in the agent's context: a prompt injection could send it anywhere, and even a correct call to the
key's own provider needed human approval because the inspector saw a secret leaving.

Separately, claims like "the flow rules never allow a leak" rested on examples, a fuzzer and replays. The
question an interviewer asks is "how do you know?"

## Decision

**Credential injection.** Operators store a secret with the destinations it may be sent to and the agents
that may use it. Agents write a handle, `{{secret:razorpay}}`, wherever the key belongs. Before policy runs,
the gateway checks every handle: the secret exists, this agent may use it, and every destination of the call
matches the secret's allowed destinations, or the request is blocked (rule S1). The handle is replaced by the
value only at execution, after the decision, and tool output is scrubbed back to the handle (plain, base64,
hex, URL-encoded). The decision path, the audit trail and the agent's context never contain the key.

**Evidence that it works, in four layers**, each answering a different doubt:

| Doubt | Answer | Where |
|---|---|---|
| "Does it stop real attacks?" | Reconstructions of published incidents, replayed with each layer on and off | `docs/benchmarks.md` |
| "What about cases you didn't think of?" | Model-based fuzzing (70,000 random steps) and exhaustive exploration of every reachable state of a small world (112 states, closed at depth 8) | `tests/test_flow_fuzz.py`, `tests/test_flow_model_check.py` |
| "Are your tests any good?" | Mutation testing: bugs planted in the engine must make the tests fail, including bugs that make it too strict | commit messages, findings log |
| "Can I try?" | A self-checking demo, a playground where anyone types their own attack, and a real Gemini agent | `examples/` |

## Alternatives considered

- **Short-lived scoped tokens per call instead of handles.** Better where the provider supports them; most
  third-party APIs take a static key, which is what handles cover. The two combine.
- **An LLM judge that reads each request.** Not deterministic, and it can be injected through the same text.
- **Formal proof (TLA+, Coq).** Stronger, but the model would be a second implementation to keep in sync.
  Exhaustive exploration runs the real code.

## Consequences

- The API-key trace moves from approval to allow, and the playground shows a hijacked agent failing to send
  the handle anywhere useful.
- Values still live in process memory; production should load them from a KMS.
- The model check covers a small world; its caveat (what the state key does not capture) is written at the
  top of the test.
