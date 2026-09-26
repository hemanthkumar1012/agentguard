const DEFAULT_BACKEND_URL = "https://agentguard-api-gba3.onrender.com";
const form = document.getElementById("form");
const backendUrl = document.getElementById("backendUrl");
const agentId = document.getElementById("agentId");
const browserToken = document.getElementById("browserToken");
const enabled = document.getElementById("enabled");
const message = document.getElementById("message");

function notify(text, good = true) {
  message.textContent = text;
  message.dataset.state = good ? "good" : "bad";
}

async function load() {
  const config = await chrome.runtime.sendMessage({ type: "get-config" });
  const tokenStatus = await chrome.runtime.sendMessage({ type: "token-status" });
  backendUrl.value = config?.backendUrl || DEFAULT_BACKEND_URL;
  agentId.value = config?.agentId || "";
  browserToken.value = config?.browserToken || "";
  enabled.checked = Boolean(config?.enabled && !tokenStatus?.expired);
  const expiry = tokenStatus?.expires_at ? new Date(tokenStatus.expires_at).toLocaleString() : "not detected";
  notify(tokenStatus?.expired ? `Browser token expired at ${expiry}. Issue a new token.` : `Browser token expiry: ${expiry}`, !tokenStatus?.expired);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await chrome.runtime.sendMessage({
    type: "save-config",
    value: {
      backendUrl: backendUrl.value.trim().replace(/\/$/, ""),
      agentId: agentId.value.trim(),
      browserToken: browserToken.value.trim(),
      enabled: enabled.checked
    }
  });
  notify("Configuration saved. Reload the AI tab to apply it.");
  await load();
});

document.getElementById("test").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({
    type: "save-config",
    value: {
      backendUrl: backendUrl.value.trim().replace(/\/$/, ""),
      agentId: agentId.value.trim(),
      browserToken: browserToken.value.trim(),
      enabled: enabled.checked
    }
  });
  const response = await chrome.runtime.sendMessage({ type: "test-connection" });
  notify(response?.ok ? "Token accepted by the AgentGuard browser gateway." : (response?.error || "Token test failed."), Boolean(response?.ok));
});

load();
