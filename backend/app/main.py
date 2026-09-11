from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response
from uuid import uuid4

from app.api.agents import router as agents_router
from app.api.anomaly import router as anomaly_router
from app.api.approvals import router as approvals_router
from app.api.control_plane import router as control_plane_router
from app.api.decisions import router as decisions_router
from app.api.delegations import router as delegations_router
from app.api.gateway import router as gateway_router
from app.api.health import router as health_router
from app.api.mcp import router as mcp_router
from app.api.security import router as security_router
from app.api.simulator import router as simulator_router
from app.api.tools import router as tools_router
from app.config import settings

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Runtime security and authorization control plane for AI agents.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_boundary(request: Request, call_next):
    if settings.api_key and request.url.path.startswith("/api/v1") and not request.url.path.startswith("/api/v1/health"):
        supplied = request.headers.get("x-api-key") or request.headers.get("authorization", "").removeprefix("Bearer ")
        if supplied != settings.api_key:
            return Response(content='{"detail":"Unauthorized"}', status_code=401, media_type="application/json")

    request_id = request.headers.get("x-request-id", f"req_{uuid4().hex[:16]}")
    response: Response = await call_next(request)
    response.headers["x-request-id"] = request_id
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["cache-control"] = "no-store"
    return response


@app.get("/", tags=["health"])
def root():
    return {"service": settings.app_name, "version": app.version, "environment": settings.environment}


app.include_router(health_router, prefix="/api/v1")
app.include_router(agents_router, prefix="/api/v1")
app.include_router(decisions_router, prefix="/api/v1")
app.include_router(gateway_router, prefix="/api/v1")
app.include_router(security_router, prefix="/api/v1")
app.include_router(anomaly_router, prefix="/api/v1")
app.include_router(simulator_router, prefix="/api/v1")
app.include_router(tools_router, prefix="/api/v1")
app.include_router(mcp_router, prefix="/api/v1")
app.include_router(control_plane_router, prefix="/api/v1")
app.include_router(approvals_router, prefix="/api/v1")
app.include_router(delegations_router, prefix="/api/v1")
