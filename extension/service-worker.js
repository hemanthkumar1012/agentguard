const DEFAULT_BACKEND_URL = "https://agentguard-api-gba3.onrender.com";

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(["backendUrl", "enabled"]);
  await chrome.storage.local.set({
    backendUrl: current.backendUrl || DEFAULT_BACKEND_URL,
    enabled: current.enabled ?? false
  });
  try {
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  } catch {
    // Older Chrome builds may not expose this behavior.
  }
});

chrome.runtime.onStartup.addListener(async () => {
  try {
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  } catch {
    // No-op.
  }
});

async function config() {
  return chrome.storage.local.get(["backendUrl", "agentId", "browserToken", "enabled", "lastDecision"]);
}

async function backendRequest(path, options = {}) {
  const settings = await config();
  if (!settings.enabled || !settings.agentId || !settings.browserToken) {
    throw new Error("AgentGuard browser protection is not configured");
  }

  const base = (settings.backendUrl || DEFAULT_BACKEND_URL).replace(/\/$/, "");
  const response = await fetch(`${base}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${settings.browserToken}`,
      ...(options.headers || {})
    },
    cache: "no-store"
  });

  const text = await response.text();
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch { body = { detail: text || "Invalid backend response" }; }
  if (!response.ok) {
    throw new Error(body.detail || `AgentGuard request failed (${response.status})`);
  }
  return body;
}

async function storeDecision(decision) {
  const snapshot = {
    ...decision,
    received_at: new Date().toISOString()
  };
  await chrome.storage.local.set({ lastDecision: snapshot });
  try {
    await chrome.runtime.sendMessage({ type: "decision-updated", decision: snapshot });
  } catch {
    // Side panel may not be open.
  }
  return snapshot;
}

async function inspect(payload) {
  const body = await backendRequest("/browser/v1/inspect", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  return storeDecision(body);
}

async function approvalStatus(approvalId) {
  return backendRequest(`/browser/v1/approvals/${encodeURIComponent(approvalId)}`);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "get-config") {
    config().then(sendResponse).catch((error) => sendResponse({ error: error.message }));
    return true;
  }

  if (message?.type === "save-config") {
    chrome.storage.local.set(message.value || {}).then(() => sendResponse({ ok: true })).catch((error) => sendResponse({ error: error.message }));
    return true;
  }

  if (message?.type === "inspect") {
    inspect(message.payload || {})
      .then((body) => sendResponse({ ok: true, body }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "approval-status") {
    approvalStatus(message.approvalId)
      .then((body) => sendResponse({ ok: true, body }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message?.type === "test-connection") {
    (async () => {
      const settings = await config();
      if (!settings?.agentId || !settings?.browserToken) {
        throw new Error("Enter an agent ID and browser token first");
      }
      const base = (settings.backendUrl || DEFAULT_BACKEND_URL).replace(/\/$/, "");
      const response = await fetch(`${base}/browser/v1/health`, {
        headers: { authorization: `Bearer ${settings.browserToken}` },
        cache: "no-store"
      });
      const text = await response.text();
      let body = {};
      try { body = text ? JSON.parse(text) : {}; } catch {}
      if (!response.ok) {
        throw new Error(body.detail || `Token test failed (${response.status})`);
      }
      sendResponse({ ok: body.status === "ok", body });
    })().catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  return false;
});

chrome.commands?.onCommand?.addListener(() => {
  // Reserved for a future keyboard shortcut.
});
