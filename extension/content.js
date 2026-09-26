const AG = {
  busy: false,
  bypass: false,
  lastComposer: null,
  badge: null,
  overlay: null,
  scanStartedAt: 0
};

const AI_SITE_LABELS = {
  "chatgpt.com": "ChatGPT",
  "chat.openai.com": "ChatGPT",
  "claude.ai": "Claude",
  "gemini.google.com": "Gemini",
  "copilot.microsoft.com": "Copilot",
  "www.perplexity.ai": "Perplexity"
};

function visible(element) {
  if (!element) return false;
  const rect = element.getBoundingClientRect();
  const style = window.getComputedStyle(element);
  return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
}

function textOf(element) {
  return element?.value ?? element?.innerText ?? element?.textContent ?? "";
}

function findComposer(preferred = null) {
  if (preferred && visible(preferred) && textOf(preferred).trim()) return preferred;
  const selectors = [
    "textarea",
    "[contenteditable='true'][role='textbox']",
    "[contenteditable='true']"
  ];
  const candidates = [...document.querySelectorAll(selectors.join(","))]
    .filter(visible)
    .filter((item) => !(item instanceof HTMLInputElement))
    .sort((a, b) => {
      const ar = a.getBoundingClientRect();
      const br = b.getBoundingClientRect();
      return (br.bottom + br.width * 0.1) - (ar.bottom + ar.width * 0.1);
    });
  const nonEmpty = candidates.find((item) => textOf(item).trim());
  return nonEmpty || candidates[0] || null;
}

function findSendButton(composer) {
  const root = composer?.closest("form") || composer?.parentElement || document.body;
  const buttons = [...root.querySelectorAll("button")].filter(visible);
  const score = (button) => {
    const label = [
      button.getAttribute("aria-label"),
      button.getAttribute("title"),
      button.getAttribute("data-testid"),
      button.innerText
    ].filter(Boolean).join(" ").toLowerCase();
    if (/stop|cancel|close|clear|attach|upload/.test(label)) return -100;
    if (/send|submit|ask|run|generate|go/.test(label)) return 10;
    if (button.querySelector("svg")) return 1;
    return 0;
  };
  return buttons.sort((a, b) => score(b) - score(a))[0] || null;
}

function showBadge(text, state = "idle") {
  if (!AG.badge) {
    AG.badge = document.createElement("div");
    AG.badge.className = "ag-badge";
    document.documentElement.appendChild(AG.badge);
  }
  AG.badge.dataset.state = state;
  AG.badge.textContent = `AG · ${text}`;
}

function showOverlay(title, body, state = "info", actions = []) {
  AG.overlay?.remove();
  const wrap = document.createElement("div");
  wrap.className = "ag-overlay";
  wrap.innerHTML = `
    <div class="ag-card" data-state="${state}">
      <div class="ag-card-title">${escapeHtml(title)}</div>
      <div class="ag-card-body">${escapeHtml(body)}</div>
      <div class="ag-card-actions"></div>
    </div>
  `;
  const actionBox = wrap.querySelector(".ag-card-actions");
  for (const action of actions) {
    const button = document.createElement("button");
    button.textContent = action.label;
    button.addEventListener("click", action.onClick);
    actionBox.appendChild(button);
  }
  document.documentElement.appendChild(wrap);
  AG.overlay = wrap;
  return wrap;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[char]);
}

function siteContext() {
  const hostname = location.hostname;
  return {
    site: hostname,
    provider: AI_SITE_LABELS[hostname] || "Supported AI site",
    page_url: location.href,
    page_title: document.title
  };
}

async function getConfig() {
  return chrome.runtime.sendMessage({ type: "get-config" });
}

async function inspectPrompt(composer, trigger = "click", sendButton = null) {
  if (AG.busy || AG.bypass) return;
  const value = textOf(composer).trim();
  if (!value) return;

  const config = await getConfig();
  if (!config?.enabled || !config?.agentId || !config?.browserToken) {
    showBadge("SETUP REQUIRED", "warn");
    return;
  }

  AG.busy = true;
  AG.scanStartedAt = Date.now();
  AG.lastComposer = composer;
  showBadge("SCANNING", "scan");

  const payload = {
    ...siteContext(),
    action: "submit_prompt",
    target: location.hostname,
    content: value,
    correlation_id: `browser_${Date.now()}_${Math.random().toString(16).slice(2)}`
  };

  const first = await chrome.runtime.sendMessage({ type: "inspect", payload });
  if (!first?.ok) {
    AG.busy = false;
    showBadge("BACKEND OFFLINE · BLOCKED", "block");
    showOverlay(
      "AgentGuard blocked the interaction",
      first?.error || "Security service unavailable. Protection is fail-closed.",
      "block",
      [{ label: "Dismiss", onClick: () => AG.overlay?.remove() }]
    );
    return;
  }

  await handleDecision(first.body, composer, sendButton, payload);
}

async function handleDecision(result, composer, sendButton, originalPayload) {
  const decision = result?.decision;
  if (decision === "allow") {
    AG.busy = false;
    showBadge("ALLOWED", "allow");
    resumeInteraction(composer, sendButton);
    return;
  }

  if (decision === "block") {
    AG.busy = false;
    showBadge("BLOCKED", "block");
    showOverlay(
      "Action blocked by AgentGuard",
      `${result.reason} · risk ${Math.round(result.risk_score)}/100`,
      "block",
      [{ label: "Dismiss", onClick: () => AG.overlay?.remove() }]
    );
    return;
  }

  if (decision === "require_approval" && result.approval_id) {
    showBadge("APPROVAL REQUIRED", "approval");
    showOverlay(
      "Human approval required",
      `${result.reason} · risk ${Math.round(result.risk_score)}/100 · approval ${result.approval_id}`,
      "approval",
      [{ label: "Cancel", onClick: () => { AG.busy = false; AG.overlay?.remove(); showBadge("READY", "idle"); } }]
    );

    const approvalId = result.approval_id;
    const poll = async () => {
      const status = await chrome.runtime.sendMessage({ type: "approval-status", approvalId });
      if (!status?.ok) {
        AG.busy = false;
        showBadge("APPROVAL CHECK FAILED", "block");
        return;
      }

      if (status.body.status === "approved") {
        const resumed = await chrome.runtime.sendMessage({
          type: "inspect",
          payload: { ...originalPayload, approval_id: approvalId }
        });
        if (resumed?.ok && resumed.body.decision === "allow") {
          AG.overlay?.remove();
          AG.busy = false;
          showBadge("APPROVED · SENT", "allow");
          resumeInteraction(composer, sendButton);
        } else {
          AG.busy = false;
          showBadge("APPROVAL RECHECK FAILED", "block");
        }
        return;
      }

      if (status.body.status === "denied" || status.body.status === "expired") {
        AG.busy = false;
        showBadge(`APPROVAL ${status.body.status.toUpperCase()}`, "block");
        AG.overlay?.remove();
        showOverlay(
          `Action ${status.body.status}`,
          status.body.decision_note || "The action was not approved.",
          "block",
          [{ label: "Dismiss", onClick: () => AG.overlay?.remove() }]
        );
        return;
      }

      setTimeout(poll, 2000);
    };

    poll();
    return;
  }

  AG.busy = false;
  showBadge("BLOCKED", "block");
}

function resumeInteraction(composer, sendButton) {
  AG.bypass = true;
  try {
    if (sendButton) {
      sendButton.click();
    } else {
      composer.dispatchEvent(new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        keyCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true
      }));
    }
  } finally {
    setTimeout(() => { AG.bypass = false; }, 500);
  }
}

function composerForEvent(target) {
  if (target instanceof HTMLTextAreaElement || target?.isContentEditable) return target;
  return findComposer(AG.lastComposer);
}

function looksLikeSendButton(target) {
  const button = target?.closest?.("button");
  if (!button || !visible(button)) return null;
  const label = [
    button.getAttribute("aria-label"),
    button.getAttribute("title"),
    button.getAttribute("data-testid"),
    button.innerText
  ].filter(Boolean).join(" ").toLowerCase();
  return /send|submit|ask|run|generate|go/.test(label) ? button : null;
}



document.addEventListener("submit", (event) => {
  if (AG.bypass || AG.busy) return;
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;

  const composer = findComposer(form.querySelector(
    "textarea, [contenteditable='true'][role='textbox'], [contenteditable='true']"
  ));
  if (!composer || !textOf(composer).trim()) return;

  event.preventDefault();
  event.stopImmediatePropagation();
  inspectPrompt(composer, "submit", findSendButton(composer));
}, true);

document.addEventListener("click", (event) => {
  if (AG.bypass || AG.busy) return;
  const button = looksLikeSendButton(event.target);
  if (!button) return;
  const composer = findComposer();
  if (!composer || !textOf(composer).trim()) return;
  event.preventDefault();
  event.stopImmediatePropagation();
  inspectPrompt(composer, "click", button);
}, true);

document.addEventListener("keydown", (event) => {
  if (AG.bypass || AG.busy) return;
  if (event.key !== "Enter" || event.shiftKey || event.isComposing || event.ctrlKey || event.metaKey) return;
  const composer = composerForEvent(event.target);
  if (!composer || !textOf(composer).trim()) return;
  const sendButton = findSendButton(composer);
  event.preventDefault();
  event.stopImmediatePropagation();
  inspectPrompt(composer, "enter", sendButton);
}, true);

setTimeout(async () => {
  const config = await getConfig();
  showBadge(config?.enabled && config?.agentId && config?.browserToken ? "READY" : "SETUP REQUIRED", config?.enabled ? "idle" : "warn");
}, 0);

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && !AG.busy) {
    getConfig().then((config) => {
      showBadge(config?.enabled && config?.agentId && config?.browserToken ? "READY" : "SETUP REQUIRED", config?.enabled ? "idle" : "warn");
    }).catch(() => showBadge("SETUP REQUIRED", "warn"));
  }
});


document.documentElement.dataset.agentguardLoaded = "true";
