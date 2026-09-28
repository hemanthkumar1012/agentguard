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
## Deterministic browser lab

For an end-to-end browser test that does not depend on a changing third-party AI DOM, serve extension/test-page.html locally:

```bash
python -m http.server 4173 --directory extension
```

Then:

1. Load the extension/ folder as an unpacked extension at chrome://extensions.
2. Configure an active AgentGuard agent with submit_prompt.
3. Issue a browser token from the AgentGuard control plane.
4. Paste the browser token into the extension options and enable protection.
5. Open http://localhost:4173/test-page.html.
6. Submit a normal prompt and confirm the simulated AI result appears only after an ALLOW decision.
7. Submit the sample api_key=... text and confirm AgentGuard pauses the submission with REQUIRE_APPROVAL.
8. Approve the request from the AgentGuard control plane and confirm the simulated AI receives it.
9. Reject or let the approval expire and confirm the simulated AI never receives it.
10. Disable the backend or use an expired/tampered browser token and confirm the extension remains blocked.

This lab validates browser interception and the live backend decision path without giving the extension broad access to unrelated websites.
## Live backend smoke test

After issuing a browser token from the AgentGuard control plane, test the deployed browser gateway without exposing the operator API key to the extension.

PowerShell:

```powershell
$env:AGENTGUARD_BROWSER_API_URL="https://agentguard-api-gba3.onrender.com"
$env:AGENTGUARD_BROWSER_AGENT_ID="agt_..."
$env:AGENTGUARD_BROWSER_TOKEN="..."
node extension/e2e/live-smoke.js
```

The smoke test verifies that the deployed browser gateway authenticates the token, a normal prompt returns ALLOW, and a prompt containing a test API-key pattern creates REQUIRE_APPROVAL.

The approval is intentionally not auto-approved by this script. Use the AgentGuard control plane to approve the returned approval_id, then validate the extension's approval polling path in the browser lab.