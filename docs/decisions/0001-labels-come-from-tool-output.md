# 0001. Labels come from what tools returned, not from what the agent says

Date: 2026-11-27. Status: accepted.

## Context

Every decision input except identity and permissions was supplied by the agent: `risk_score`,
`data_classification`, even the description of the content. The threat AgentGuard exists for is an
agent that has been taken over by a prompt injection. Such an agent will declare whatever passes.
Probe: an agent that had just read a customer record sent `risk_score: 0, data_classification: "public"`
and exported the record. The decision was `allow`.

## Decision

AgentGuard works out the sensitive facts itself, from the tool calls it authorises and runs:

- Each tool action has a **manifest**, registered by an operator, that says what it can do:
  `reads_private`, `ingests_untrusted`, `egress`, `mutates`, plus where the destination is in the
  payload and who may read its private output.
- Each **session** has a label that grows with every allowed call: "has read untrusted content",
  "has read private data readable by R".
- When AgentGuard executes the tool (`/tools/execute`, `/mcp/call`) it also sees the output, so it
  can fingerprint private data (see 0003) and read the owner of a single record from the output.

Agents cannot reset their label. Sessions are created by an operator key (`POST /flow/sessions`,
admin only). A request without `session_id` goes to the agent's long-lived default session, not a
fresh one. A request naming a session that does not exist, is closed or belongs to another agent is
blocked (rule F0).

A tool with no manifest is assumed to be able to send data out, change state and return untrusted
text. It is not assumed to return private data: if every unknown output were private, every later
request would be blocked, and a label that is always "everything" carries no information.

## Alternatives considered

- **Keep agent-declared labels and validate them with an LLM classifier.** Rejected for the decision
  path: an LLM judging an LLM can be prompt-injected through the same content, and it is not
  deterministic, so decisions cannot be replayed or tested.
- **Static per-agent capability limits only** (the Rule of Two applied at configuration time). Useful,
  but too coarse: a support agent legitimately needs untrusted input, private data and email. The
  dangerous thing is one specific flow, not the combination of capabilities.

## Consequences

- Operators must describe their tools. Undescribed tools get the worst-case manifest and the
  `undescribed-tool-assumed-worst-case` risk factor, so gaps show up in the audit trail.
- In authorize-only mode (`/decisions`, `/gateway/authorize`) AgentGuard never sees outputs: labels
  still grow from manifests, but there are no fingerprints.
- Labels are in process memory for now (see the open issues in `docs/findings-log.md`).
