import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

// Browser -> console server -> SentinelForge API. The operator key stays on the server, and
// only these method/path shapes are forwarded. Admin-only mutations that the console does not
// need (replacing the policy pack, registering identities, revoking credentials) are not exposed.
const ALLOWED: { method: "GET" | "POST"; pattern: RegExp }[] = [
  { method: "GET", pattern: /^traces$/ },
  { method: "GET", pattern: /^traces\/trc_[a-z0-9]+$/ },
  { method: "GET", pattern: /^observability\/stats$/ },
  { method: "GET", pattern: /^budgets\/[a-z0-9_-]+$/ },
  { method: "GET", pattern: /^agent-versions$/ },
  { method: "GET", pattern: /^approvals$/ },
  { method: "GET", pattern: /^approvals\/apr_[a-z0-9]+$/ },
  { method: "GET", pattern: /^policies$/ },
  { method: "GET", pattern: /^policies\/history$/ },
  { method: "GET", pattern: /^evaluations$/ },
  { method: "GET", pattern: /^evaluations\/datasets$/ },
  { method: "GET", pattern: /^evaluations\/eval_[a-z0-9]+$/ },
  { method: "GET", pattern: /^orchestrations\/agents$/ },
  { method: "POST", pattern: /^runs$/ },
  { method: "POST", pattern: /^runs\/trc_[a-z0-9]+\/resume$/ },
  { method: "POST", pattern: /^approvals\/apr_[a-z0-9]+\/decision$/ },
  { method: "POST", pattern: /^evaluations$/ },
  { method: "POST", pattern: /^evaluations\/compare$/ },
  { method: "POST", pattern: /^agent-versions\/[a-z0-9.-]+\/promote$/ },
  { method: "POST", pattern: /^redteam\/run$/ },
  { method: "POST", pattern: /^orchestrations\/run$/ },
  { method: "POST", pattern: /^policies\/simulate$/ },
];

const MAX_BODY_BYTES = 64 * 1024;

async function forward(request: Request, path: string[], method: "GET" | "POST") {
  const backendUrl = process.env.AGENTGUARD_BACKEND_URL;
  const apiKey = process.env.SENTINELFORGE_CONSOLE_KEY ?? process.env.AGENTGUARD_API_KEY;
  const joined = path.join("/");
  if (!backendUrl || !apiKey) {
    return NextResponse.json({ detail: "Console backend is not configured" }, { status: 503, headers: { "cache-control": "no-store" } });
  }
  if (!ALLOWED.some((rule) => rule.method === method && rule.pattern.test(joined))) {
    return NextResponse.json({ detail: "Not available from the console" }, { status: 404, headers: { "cache-control": "no-store" } });
  }

  const upstream = new URL(`/api/v1/${joined}`, backendUrl);
  if (method === "GET") {
    new URL(request.url).searchParams.forEach((value, key) => upstream.searchParams.set(key, value));
  }
  let body: string | undefined;
  if (method === "POST") {
    body = await request.text();
    if (body.length > MAX_BODY_BYTES) {
      return NextResponse.json({ detail: "Request body too large" }, { status: 413 });
    }
  }
  try {
    const response = await fetch(upstream, {
      method,
      headers: {
        authorization: `Bearer ${apiKey}`,
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        ...(request.headers.get("x-request-id") ? { "x-request-id": request.headers.get("x-request-id")! } : {}),
      },
      body,
      cache: "no-store",
    });
    return new NextResponse(await response.text(), {
      status: response.status,
      headers: { "content-type": response.headers.get("content-type") ?? "application/json", "cache-control": "no-store" },
    });
  } catch {
    return NextResponse.json({ detail: "Console backend is unavailable" }, { status: 502, headers: { "cache-control": "no-store" } });
  }
}

export async function GET(request: Request, context: { params: Promise<{ path: string[] }> }) {
  return forward(request, (await context.params).path, "GET");
}

export async function POST(request: Request, context: { params: Promise<{ path: string[] }> }) {
  return forward(request, (await context.params).path, "POST");
}
