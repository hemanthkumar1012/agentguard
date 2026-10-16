const base = (process.env.AGENTGUARD_BROWSER_API_URL || "https://agentguard-api-gba3.onrender.com").replace(/\/$/, "");
const token = process.env.AGENTGUARD_BROWSER_TOKEN;
const agentId = process.env.AGENTGUARD_BROWSER_AGENT_ID;

if (!token || !agentId) {
  console.error("Set AGENTGUARD_BROWSER_TOKEN and AGENTGUARD_BROWSER_AGENT_ID before running this smoke test.");
  process.exit(2);
}

async function call(path, body) {
  const response = await fetch(`${base}${path}`, {
    method: body ? "POST" : "GET",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  return { status: response.status, data };
}

async function main() {
  const health = await call("/browser/v1/health");
  console.log("health:", health.status, health.data);
  if (health.status !== 200 || health.data.agent_id !== agentId) process.exit(1);

  const allow = await call("/browser/v1/inspect", {
    site: "live-smoke",
    page_url: "https://example.invalid/agentguard-smoke",
    page_title: "AgentGuard live smoke test",
    action: "submit_prompt",
    target: "live-smoke",
    content: "Summarize this public smoke-test message.",
  });
  console.log("allow:", allow.status, allow.data);
  if (allow.status !== 200 || allow.data.decision !== "allow") process.exit(1);

  const approval = await call("/browser/v1/inspect", {
    site: "live-smoke",
    page_url: "https://example.invalid/agentguard-smoke",
    page_title: "AgentGuard live approval test",
    action: "submit_prompt",
    target: "live-smoke",
    content: "Use api_key=sk_live_1234567890abcdef only for this security test.",
  });
  console.log("approval:", approval.status, approval.data);
  if (approval.status !== 200 || approval.data.decision !== "require_approval" || !approval.data.approval_id) process.exit(1);

  console.log("AgentGuard live browser smoke test: PASS");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});