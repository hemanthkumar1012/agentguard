const fs = require("fs");
const path = require("path");

const root = __dirname;
const dist = path.join(root, "dist", "agentguard-browser-extension");
fs.rmSync(path.join(root, "dist"), { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });

const include = new Set([
  "manifest.json",
  "content.js",
  "content.css",
  "service-worker.js",
  "sidepanel.html",
  "sidepanel.js",
  "panel.css",
  "options.html",
  "options.js",
  "options.css"
]);
for (const file of include) {
  fs.copyFileSync(path.join(root, file), path.join(dist, file));
}

const manifest = JSON.parse(fs.readFileSync(path.join(dist, "manifest.json"), "utf8"));
if (manifest.host_permissions.some((value) => value.startsWith("http://localhost"))) {
  throw new Error("Release manifest contains localhost permissions");
}
if (manifest.permissions.includes("activeTab")) {
  throw new Error("Release manifest contains unnecessary activeTab permission");
}
if (manifest.content_scripts.some((entry) => entry.matches.some((value) => value.startsWith("http://localhost")))) {
  throw new Error("Release manifest contains localhost content-script matches");
}
console.log(`Release extension prepared: ${dist}`);