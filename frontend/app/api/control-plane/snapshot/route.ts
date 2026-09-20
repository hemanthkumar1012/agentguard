import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const backendUrl = process.env.AGENTGUARD_BACKEND_URL;
  const apiKey = process.env.AGENTGUARD_API_KEY;

  if (!backendUrl || !apiKey) {
    return NextResponse.json(
      { detail: "Dashboard backend is not configured" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }

  const upstream = new URL("/api/v1/control-plane/snapshot", backendUrl);
  const requestId = request.headers.get("x-request-id");

  try {
    const response = await fetch(upstream, {
      method: "GET",
      headers: {
        authorization: `Bearer ${apiKey}`,
        ...(requestId ? { "x-request-id": requestId } : {}),
      },
      cache: "no-store",
    });

    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "application/json",
        "cache-control": "no-store",
        ...(response.headers.get("x-request-id") ? { "x-request-id": response.headers.get("x-request-id")! } : {}),
      },
    });
  } catch {
    return NextResponse.json(
      { detail: "Dashboard backend is unavailable" },
      { status: 502, headers: { "cache-control": "no-store" } },
    );
  }
}
