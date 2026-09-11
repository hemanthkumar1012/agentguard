from fastapi import FastAPI

from app.api.agents import router as agents_router
from app.api.anomaly import router as anomaly_router
from app.api.decisions import router as decisions_router
from app.api.gateway import router as gateway_router
from app.api.health import router as health_router
from app.api.security import router as security_router

app = FastAPI(
    title="AgentGuard API",
    version="0.5.0",
    description="Runtime security and authorization control plane for AI agents.",
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(agents_router, prefix="/api/v1")
app.include_router(decisions_router, prefix="/api/v1")
app.include_router(gateway_router, prefix="/api/v1")
app.include_router(security_router, prefix="/api/v1")
app.include_router(anomaly_router, prefix="/api/v1")
