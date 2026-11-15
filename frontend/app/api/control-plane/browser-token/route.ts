import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const backendUrl = process.env.AGENTGUARD_BACKEND_URL;
  const apiKey = process.env.AGENTGUARD_API_KEY;

  if (!backendUrl || !apiKey) {
    return NextResponse.json(
      { detail: "Dashboard backend is not configured" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }

  const body = await request.text();
  try {
    const response = await fetch(new URL("/api/v1/security/browser-token", backendUrl), {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body,
      cache: "no-store",
    });
    const responseBody = await response.text();
    return new NextResponse(responseBody, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "application/json",
        "cache-control": "no-store",
      },
    });
  } catch {
    return NextResponse.json(
      { detail: "Browser token service is unavailable" },
      { status: 502, headers: { "cache-control": "no-store" } },
    );
  }
}
