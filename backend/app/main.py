from fastapi import FastAPI

from app.api.agents import router as agents_router
from app.api.anomaly import router as anomaly_router
from app.api.decisions import router as decisions_router
from app.api.gateway import router as gateway_router
from app.api.health import router as health_router
from app.api.mcp import router as mcp_router
from app.api.security import router as security_router
from app.api.simulator import router as simulator_router
from app.api.tools import router as tools_router

app = FastAPI(
    title="AgentGuard API",
    version="0.8.0",
    description="Runtime security and authorization control plane for AI agents.",
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(agents_router, prefix="/api/v1")
app.include_router(decisions_router, prefix="/api/v1")
app.include_router(gateway_router, prefix="/api/v1")
app.include_router(security_router, prefix="/api/v1")
app.include_router(anomaly_router, prefix="/api/v1")
app.include_router(simulator_router, prefix="/api/v1")
app.include_router(tools_router, prefix="/api/v1")
app.include_router(mcp_router, prefix="/api/v1")
