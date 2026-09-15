import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
const allowedResources = new Set(["agents", "events", "approvals", "credentials"]);

export async function GET(request: Request, context: { params: Promise<{ resource: string }> }) {
  const { resource } = await context.params;
  const backendUrl = process.env.AGENTGUARD_BACKEND_URL;
  const apiKey = process.env.AGENTGUARD_API_KEY;
  if (!backendUrl || !apiKey || !allowedResources.has(resource)) {
    return NextResponse.json({ detail: "Dashboard resource is unavailable" }, { status: 503, headers: { "cache-control": "no-store" } });
  }

  const paths: Record<string, string> = {
    agents: "/api/v1/agents",
    events: "/api/v1/gateway/audit",
    approvals: "/api/v1/approvals",
    credentials: "/api/v1/security/credentials",
  };
  try {
    const response = await fetch(new URL(paths[resource], backendUrl), {
      headers: { authorization: `Bearer ${apiKey}` },
      cache: "no-store",
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: { "content-type": response.headers.get("content-type") ?? "application/json", "cache-control": "no-store" },
    });
  } catch {
    return NextResponse.json({ detail: "Dashboard backend is unavailable" }, { status: 502, headers: { "cache-control": "no-store" } });
  }
}
