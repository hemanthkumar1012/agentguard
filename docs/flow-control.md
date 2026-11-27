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

## 5. Rolling out

Set `AGENTGUARD_FLOW_MODE=monitor` first. Decisions do not change, but every request that *would* have
been stopped gets a `flow-would-block` or `flow-would-require_approval` risk factor in the audit trail.
Review those, fix manifests and destinations, then switch to `enforce` (the default). `off` disables the
feature.
