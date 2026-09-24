from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app.browser_auth import issue_browser_token, verify_browser_token
from app.domain import ActionRequest
from app.identity import AgentStatus
from app.services import agent_registry, approval_store, tool_gateway

router = APIRouter(tags=["browser"])


class BrowserTokenRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=100)
    ttl_seconds: int = Field(default=86_400, ge=300, le=604_800)


class BrowserInspectRequest(BaseModel):
    site: str = Field(min_length=1, max_length=200)
    page_url: str = Field(min_length=1, max_length=2000)
    page_title: str = Field(default="", max_length=500)
    action: str = Field(default="submit_prompt", min_length=1, max_length=100)
    target: str = Field(default="browser", min_length=1, max_length=500)
    data_classification: str = Field(default="public", min_length=1, max_length=50)
    content: str = Field(min_length=1, max_length=100_000)
    correlation_id: str | None = Field(default=None, max_length=100)
    approval_id: str | None = Field(default=None, max_length=100)


def _claims(authorization: str | None, required_scope: str = "browser:inspect") -> dict[str, Any]:
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Browser token required")
    try:
        return verify_browser_token(token, required_scope=required_scope)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.post("/api/v1/security/browser-token")
def create_browser_token(request: BrowserTokenRequest):
    agent = agent_registry.get(request.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent identity not found")
    if agent.status != AgentStatus.ACTIVE:
        raise HTTPException(status_code=409, detail=f"Agent identity is {agent.status.value}")
    token, exp = issue_browser_token(agent.agent_id, request.ttl_seconds)
    return {
        "agent_id": agent.agent_id,
        "scope": ["browser:inspect", "browser:approval"],
        "token": token,
        "expires_at": datetime.fromtimestamp(exp, tz=timezone.utc),
    }


@router.get("/browser/v1/health")
def browser_health(authorization: str | None = Header(default=None)):
    claims = _claims(authorization, required_scope="browser:inspect")
    agent = agent_registry.get(claims["sub"])
    if agent is None or agent.status != AgentStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Browser agent is unavailable")
    return {
        "status": "ok",
        "agent_id": agent.agent_id,
        "service": "agentguard-browser-gateway",
    }


@router.post("/browser/v1/inspect")
def inspect_browser_action(request: BrowserInspectRequest, authorization: str | None = Header(default=None)):
    claims = _claims(authorization)
    action = ActionRequest(
        agent_id=claims["sub"],
        action=request.action,
        target=request.target,
        data_classification=request.data_classification,
        risk_score=50,
        content=request.content,
        correlation_id=request.correlation_id,
        approval_id=request.approval_id,
        execution_payload={
            "browser": {
                "site": request.site,
                "page_url": request.page_url,
                "page_title": request.page_title,
            }
        },
    )
    result = tool_gateway.authorize(action, consume_approval=bool(request.approval_id))
    return {
        "event_id": result.event_id,
        "agent_id": result.decision.agent_id,
        "decision": result.decision.decision,
        "reason": result.decision.reason,
        "risk_score": result.decision.risk_score,
        "risk_factors": result.decision.risk_factors,
        "data_findings": result.decision.data_findings,
        "approval_id": result.decision.approval_id,
    }


@router.get("/browser/v1/approvals/{approval_id}")
def browser_approval_status(approval_id: str, authorization: str | None = Header(default=None)):
    claims = _claims(authorization, required_scope="browser:approval")
    approval = approval_store.get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.requested_by != claims["sub"]:
        raise HTTPException(status_code=403, detail="Approval does not belong to this browser agent")
    return {
        "approval_id": approval.approval_id,
        "status": approval.status,
        "expires_at": approval.expires_at,
        "decided_at": approval.decided_at,
        "decision_note": approval.decision_note,
    }
