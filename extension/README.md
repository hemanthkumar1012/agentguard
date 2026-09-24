# AgentGuard Browser Security Extension

The extension/ directory contains the first Chrome Manifest V3 browser enforcement layer for AgentGuard.

## What it protects

The extension currently supports browser-based AI applications on:

- ChatGPT
- Claude
- Gemini
- Microsoft Copilot
- Perplexity

Before a detected prompt submission is allowed to continue, the extension sends the prompt context to the deterministic AgentGuard gateway.

```text
AI prompt
   ↓
Chrome content script
   ↓
Scoped browser token
   ↓
AgentGuard /browser/v1/inspect
   ↓
identity → inspection → risk → policy
   ↓
ALLOW ───────────────→ submit prompt
REQUIRE APPROVAL ────→ pause → operator approval → recheck
BLOCK ───────────────→ prevent submission + explain
```

Backend failures are fail-closed.

## Local installation

1. Open chrome://extensions.
2. Enable Developer mode.
3. Choose Load unpacked.
4. Select this repository's extension/ directory.
5. Open the AgentGuard extension options.
6. Configure the backend URL, an AgentGuard agent ID, and its browser token.

## Create a browser agent

Create an agent through the existing protected AgentGuard API with the submit_prompt permission.

```bash
curl -X POST "$AGENTGUARD_BACKEND_URL/api/v1/agents" \
  -H "Authorization: Bearer $AGENTGUARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "browser-agent",
    "owner": "security",
    "environment": "production",
    "permissions": ["submit_prompt"]
  }'
```

Use the returned agent_id when issuing the browser token.

## Issue the browser token

Browser tokens are signed, scoped, short-lived tokens. They are not the permanent AgentGuard operator API key.

```bash
curl -X POST "$AGENTGUARD_BACKEND_URL/api/v1/security/browser-token" \
  -H "Authorization: Bearer $AGENTGUARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_...",
    "ttl_seconds": 86400
  }'
```

Paste the returned token into the extension options.

### Security boundaries

The extension never needs:

- AGENTGUARD_API_KEY
- SUPABASE_SERVICE_KEY
- tool credentials

The browser token is restricted to browser:inspect and browser:approval.
It cannot be used as an operator credential or to execute external tools.

## Current enforcement behavior

Normal prompt: ALLOW resumes the original send interaction.

Sensitive content: REQUIRE_APPROVAL stops the interaction while the existing AgentGuard approval workflow is polled for a decision.

Policy denial: BLOCK keeps the interaction stopped and shows the reason and risk score.

The extension is intentionally limited to browser-side enforcement. Native desktop agents, local processes, and arbitrary OS-level applications remain outside the browser extension boundary.