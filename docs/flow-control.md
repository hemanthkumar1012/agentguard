# Data-flow control: how to use it

Design reasoning is in `docs/decisions/0001`–`0004`; measurements are in `docs/benchmarks.md`.
This page covers setup.

## 1. Describe your tools (once, as an operator)

```bash
# CRM rows are private: readable inside the company, and by the customer the row belongs to.
curl -X POST $API/flow/manifests -H "x-api-key: $ADMIN_KEY" -H 'content-type: application/json' -d '{
  "tool": "crm", "action": "read_record", "capabilities": ["reads_private"],
  "readers": ["internal", "domain:acme.com"], "readers_from": ["email"]
}'

# Ticket bodies are written by customers, so they are untrusted.
curl -X POST $API/flow/manifests ... -d '{"tool": "helpdesk", "action": "read_ticket", "capabilities": ["ingests_untrusted"]}'

# Email sends data out; the destination is the "to" field of the payload.
curl -X POST $API/flow/manifests ... -d '{"tool": "gmail", "action": "send_email", "capabilities": ["egress"], "destination_field": "to"}'
```

Capabilities: `reads_private`, `ingests_untrusted`, `egress`, `mutates`. A tool with no manifest is
treated as `egress + mutates + ingests_untrusted`. Defaults ship for `send_email`, `export_data`,
`http_request`, `fetch_url`, `read_record`, `read_inbox`, `web_search`, `delete`, `transfer_funds`.

Only use `readers_from` on output from a system of record. If an attacker can write the field (a ticket
body, a web page), they can name themselves as a reader.

## 2. Say who reads each destination

```bash
curl -X POST $API/flow/destinations ... -d '{"pattern": "slack:#support-*", "audience": ["domain:acme.com"]}'
curl -X POST $API/flow/destinations ... -d '{"pattern": "s3://acme-analytics/*", "audience": ["internal"]}'
```

An email address is read by its recipient (`user:<address>`). Anything not registered is public (`*`).

## 3. Start a session per task

```bash
curl -X POST $API/flow/sessions ... -d '{"agent_id": "agt_…", "purpose": "ticket 4471"}'
# → {"session_id": "ses_…", "untrusted": false, "holds_private": false, "readers": null, …}
```

Pass `session_id` with every `/tools/execute`, `/mcp/call` or `/decisions` request for that task.
Without one, the agent's default session is used, which never resets. Close the session when the task
ends: `POST /flow/sessions/{id}/close`. Inspect it at any time: `GET /flow/sessions/{id}`.

## 4. What the agent sees

```json
{
  "decision": "block",
  "flow_rule": "F1",
  "reason": "Lethal trifecta: this session read untrusted content (helpdesk.read_ticket) and private data (crm.read_record, readable by domain:acme.com, internal, user:priya@gmail.com). Sending to drop@evil.io (read by user:drop@evil.io) could leak it, so the request was blocked.",
  "lineage": [{"source_event_id": "evt_…", "tool": "crm", "action": "read_record", "shared_fingerprints": 7, "coverage": 0.7, "encoding": "plain"}]
}
```

## 5. Check replies before rendering them

The model's reply can leak too: a markdown image is fetched by the client with zero clicks (EchoLeak).
Pass every reply through the output check before showing it:

```bash
curl -X POST $API/flow/check-output ... -d '{"agent_id": "agt_…", "session_id": "ses_…", "text": "<model reply>"}'
# → {"text": "<reply with leaking URLs replaced by #agentguard-removed>", "sanitised": true,
#    "removed": [{"url": "…", "kind": "image", "host": "…", "reason": "…", "lineage": […]}], "event_id": "evt_…"}
```

Render the returned `text`, never the original. A `409` (unknown session) or `503` (label store down)
means: do not render.

## 6. Several workers

Set `AGENTGUARD_FLOW_REDIS_URL=redis://host:6379/0` so all workers share labels, and run Redis with
persistence (AOF). Operator sessions expire after `AGENTGUARD_FLOW_SESSION_TTL` seconds without writes and
are then blocked. `GET /health/ready` reports `flow_labels: ok | failed | process_memory`.
Apply `supabase/migrations/0004_audit_chain_sequence.sql` so several workers keep one audit chain.

## 7. Rolling out

Set `AGENTGUARD_FLOW_MODE=monitor` first. Decisions do not change, but every request that *would* have
been stopped gets a `flow-would-block` or `flow-would-require_approval` risk factor in the audit trail.
Review those, fix manifests and destinations, then switch to `enforce` (the default). `off` disables the
feature.

## 8. Give agents handles, not keys

```bash
curl -X POST $API/vault/secrets ... -d '{"name": "razorpay", "value": "<the real key>",
  "allowed_destinations": ["https://api.razorpay.com/*"], "allowed_agents": ["agt_…"]}'
# → {"name": "razorpay", "handle": "{{secret:razorpay}}", "sha256_prefix": "…", …}   (the value is never returned)
```

The agent puts `{{secret:razorpay}}` where the key goes (for example `"Authorization": "Bearer {{secret:razorpay}}"`).
A handle in a request to any other destination, or from another agent, is blocked (rule S1). The gateway
replaces the handle only when it runs the tool, and scrubs the key out of the tool's output.
