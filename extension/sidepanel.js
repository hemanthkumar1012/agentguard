const statusEl = document.getElementById("status");
const protectionEl = document.getElementById("protection");
const agentEl = document.getElementById("agent");
const siteEl = document.getElementById("site");
const decisionEl = document.getElementById("decision");
const eventEl = document.getElementById("event");

function fmt(value) {
  return value ? new Date(value).toLocaleString() : "—";
}

async function load() {
  const config = await chrome.runtime.sendMessage({ type: "get-config" });
  const enabled = Boolean(config?.enabled && config?.agentId && config?.browserToken);
  statusEl.textContent = enabled ? "PROTECTED" : "OFF";
  statusEl.className = `pill ${enabled ? "on" : "bad"}`;
  protectionEl.textContent = enabled ? "Fail-closed protection" : "Disabled";
  agentEl.textContent = config?.agentId || "Not configured";

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  siteEl.textContent = tabs?.[0]?.url ? new URL(tabs[0].url).hostname : "—";

  const d = config?.lastDecision;
  decisionEl.textContent = d?.decision ? d.decision.replace("_", " ").toUpperCase() : "—";
  eventEl.innerHTML = d
    ? `<strong>${d.decision}</strong> · risk ${Math.round(d.risk_score || 0)}/100<br>${d.reason || "No reason returned"}<br><span style="color:#8795a8">${fmt(d.received_at)}</span>`
    : "No browser events yet.";
}

document.getElementById("refresh").addEventListener("click", load);
document.getElementById("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
document.getElementById("docs").addEventListener("click", () => {
  chrome.tabs.create({ url: "https://github.com/hemanthkumar1012/agentguard/tree/main/extension" });
});

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "decision-updated") load();
});

load();
