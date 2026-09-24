const http = require("http");
const path = require("path");
const { chromium } = require("@playwright/test");

const repoRoot = path.resolve(__dirname, "../..");
const extensionPath = path.join(repoRoot, "extension");

function startServer(port, handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

async function main() {
  let approvalReady = false;
  const backend = await startServer(8787, (req, res) => {
    if (req.url === "/browser/v1/health") {
      res.writeHead(200, {"content-type":"application/json"});
      res.end(JSON.stringify({status:"ok",agent_id:"agt_browser_e2e",service:"agentguard-browser-gateway"}));
      return;
    }
    if (req.url === "/browser/v1/approvals/apr_e2e") {
      res.writeHead(200, {"content-type":"application/json"});
      res.end(JSON.stringify({approval_id:"apr_e2e",status:approvalReady ? "approved" : "pending",expires_at:new Date(Date.now()+60000).toISOString()}));
      return;
    }
    if (req.url === "/browser/v1/inspect" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => body += chunk);
      req.on("end", () => {
        const payload = JSON.parse(body);
        const content = String(payload.content || "");
        let response;
        if (content.includes("BLOCKME")) {
          response = {event_id:"evt_block",agent_id:"agt_browser_e2e",decision:"block",reason:"Synthetic policy block",risk_score:92,risk_factors:["synthetic-test"],data_findings:[]};
        } else if (content.includes("api_key=")) {
          approvalReady = true;
          response = {event_id:"evt_approval",agent_id:"agt_browser_e2e",decision:"require_approval",reason:"Synthetic approval required",risk_score:76,risk_factors:["sensitive-test"],data_findings:["api_key"],approval_id:"apr_e2e"};
        } else {
          response = {event_id:"evt_allow",agent_id:"agt_browser_e2e",decision:"allow",reason:"Synthetic allow",risk_score:10,risk_factors:[],data_findings:[]};
        }
        res.writeHead(200, {"content-type":"application/json"});
        res.end(JSON.stringify(response));
      });
      return;
    }
    res.writeHead(404, {"content-type":"application/json"});
    res.end(JSON.stringify({detail:"Not found"}));
  });

  const staticServer = await startServer(4173, (req, res) => {
    if (req.url !== "/test-page.html") { res.writeHead(404); res.end(); return; }
    const fs = require("fs");
    const html = fs.readFileSync(path.join(extensionPath, "test-page.html"), "utf8");
    res.writeHead(200, {"content-type":"text/html; charset=utf-8"});
    res.end(html);
  });

  const context = await chromium.launchPersistentContext("", {
    headless: true,
    args: [
      "--no-sandbox",
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`
    ]
  });

  try {
    let serviceWorker = context.serviceWorkers()[0];
    if (!serviceWorker) serviceWorker = await context.waitForEvent("serviceworker");
    const extensionId = new URL(serviceWorker.url()).host;

    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/options.html`);
    await options.locator("#backendUrl").fill("http://127.0.0.1:8787");
    await options.locator("#agentId").fill("agt_browser_e2e");
    await options.locator("#browserToken").fill("e2e-token");
    await options.locator("#enabled").check();
    await options.locator("#test").click();
    await options.waitForFunction(() => document.querySelector("#message")?.dataset.state === "good");
    await options.close();

    const page = await context.newPage();
    await page.goto("http://127.0.0.1:4173/test-page.html");
    const prompt = page.locator("#prompt");
    const result = page.locator("#result");

    await prompt.fill("Summarize this public text");
    await page.locator("#send").click();
    await page.waitForFunction(() => document.querySelector("#result")?.textContent.includes("Prompt reached"));

    await prompt.fill("Send this api_key=sk_live_1234567890abcdef");
    await page.locator("#send").click();
    await page.locator(".ag-overlay").waitFor({state:"visible"});
    await result.waitForFunction((el) => el.textContent.includes("Prompt reached"), await result.elementHandle());

    await prompt.fill("BLOCKME");
    await page.locator("#send").click();
    await page.getByText("Action blocked by AgentGuard").waitFor({state:"visible"});

    console.log("AgentGuard browser E2E: PASS");
  } finally {
    await context.close();
    await new Promise((resolve) => backend.close(resolve));
    await new Promise((resolve) => staticServer.close(resolve));
  }
}

main().catch((error) => { console.error(error); process.exit(1); });