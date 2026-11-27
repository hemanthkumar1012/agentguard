# 0002. Reader sets, and when to block versus ask a human

Date: 2026-11-27. Status: accepted.

## Context

"Untrusted input + private data + a way to send data out" is the pattern behind the GitHub MCP leak
(Invariant Labs, May 2025), the Supabase MCP token leak (General Analysis, July 2025) and EchoLeak
(Aim Security, June 2025). Simon Willison calls it the lethal trifecta; Meta's "Agents Rule of Two"
(October 2025) says an agent session should have at most two of the three.

Applied literally, the rule breaks normal work: a support agent reads an untrusted ticket and a private
customer record and then emails the customer. That is all three, and it is exactly the job.

## Decision

Make the rule about **where the data goes**, using reader sets (the decentralized label model, Myers and
Liskov):

- Private data carries the principals allowed to read it, e.g. `{internal, domain:acme.com}`. A single
  CRM record also names its owner (`readers_from: ["email"]`), so the customer may read their own row.
- A session's readers are the **meet** of everything it has read: the principals allowed to read all of
  it. Reading more private data can only shrink this set.
- A destination has an audience: registered patterns (`slack:#support-*` → `{domain:acme.com}`), an
  email address → that one user, anything else → `*` (public).
- Data may flow only if every member of the audience is an allowed reader.

| Rule | Condition | Decision | Why this severity |
|---|---|---|---|
| F0 | session unknown, closed or another agent's | block | cannot reason about an unknown label |
| F1 | untrusted + private + audience outside readers | **block** | something may be steering the agent; an approval here would ask a human to judge text written by an attacker |
| F2 | private + audience outside readers, no untrusted input | approval | nothing is steering the agent, but the flow still breaks the data's reader policy |
| F3 | fingerprints of earlier private output found, audience outside its readers | block if untrusted, else approval | catches leaks across sessions that F1/F2 cannot see |
| F4 | untrusted + high-impact state change (payment, delete) | approval | Willison's critique of the Rule of Two: "untrusted input + change state" is not safe when the change is a payment |

Flow rules run after the normal policy and can only make a decision stricter.

## Alternatives considered

- **Block whenever all three capabilities are present (literal Rule of Two).** Blocks the support reply.
- **Ask a human for every trifecta flow.** Approvals that fire constantly get rubber-stamped (Meta's
  own limitation note mentions users blindly confirming warnings). Approvals are kept for the cases where
  a human can judge something useful.
- **Destination allowlist per agent.** Simpler, but it cannot say "this customer may receive their own
  data and nobody else's", which is the common case.

## Consequences

- The support reply, the internal Slack summary and the PR in the same private repo flow with no
  friction; the published attacks are blocked (see `docs/benchmarks.md`).
- **Label creep:** a session that reads two customers' records can only talk to people allowed to read
  both, so replying to either is blocked. Measured: 1 of 7 benign traces. The fix is to split work
  into sessions; CaMeL-style quarantined sub-agents would be the stronger fix.
- Readers declared through `readers_from` must come from a system of record. Output an attacker can
  write (a ticket body) must never name readers.
