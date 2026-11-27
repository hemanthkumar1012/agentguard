"""Operator API for data-flow control: sessions, tool manifests and destination audiences.

Writes need an admin operator key (see operator_auth.can_access); agents must not be able to
start a clean session for themselves or relabel a tool.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.config import settings
from app.domain import Decision
from app.flow.labels import Capability, DEFAULT_PRIVATE_READERS, ToolManifest
from app.flow.output import check_output
from app.flow.session import FlowStateUnavailable
from app.services import agent_registry, audit_ledger, flow_engine

router = APIRouter(prefix="/flow", tags=["flow"])

PRINCIPAL_PREFIXES = ("user:", "domain:", "group:")


def _check_principals(values: list[str]) -> list[str]:
    for value in values:
        if value not in {"*", "internal"} and not value.startswith(PRINCIPAL_PREFIXES):
            raise ValueError(f"'{value}' is not a principal: use *, internal, user:, domain: or group:")
    return values


class SessionCreate(BaseModel):
    agent_id: str = Field(min_length=1, max_length=100)
    purpose: str = Field(default="", max_length=200)


class ManifestUpsert(BaseModel):
    tool: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    capabilities: list[Capability] = Field(default_factory=list)
    destination_field: str | None = Field(default=None, min_length=1, max_length=100)
    readers: list[str] = Field(default_factory=lambda: sorted(DEFAULT_PRIVATE_READERS), max_length=50)
    readers_from: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("readers")
    @classmethod
    def _valid_readers(cls, value: list[str]) -> list[str]:
        return _check_principals(value)


class OutputCheckRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=100)
    session_id: str | None = Field(default=None, min_length=1, max_length=100)
    text: str = Field(max_length=200_000)


class DestinationUpsert(BaseModel):
    pattern: str = Field(min_length=1, max_length=300)
    audience: list[str] = Field(min_length=1, max_length=50)

    @field_validator("audience")
    @classmethod
    def _valid_audience(cls, value: list[str]) -> list[str]:
        return _check_principals(value)


def _manifest_dict(m: ToolManifest) -> dict:
    return {
        "tool": m.tool,
        "action": m.action,
        "capabilities": sorted(c.value for c in m.capabilities),
        "destination_field": m.destination_field,
        "readers": sorted(m.readers),
        "readers_from": list(m.readers_from),
    }


@router.get("/status")
def status():
    return {"mode": flow_engine.mode, "label_store": type(flow_engine.sessions).__name__,
            "sessions": len(flow_engine.sessions.list()),
            "manifests": len(flow_engine.manifests.list()), "destinations": len(flow_engine.destinations.rules)}


@router.post("/sessions", status_code=201)
def create_session(body: SessionCreate):
    if agent_registry.get(body.agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return flow_engine.sessions.create(body.agent_id, body.purpose).summary()


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    label = flow_engine.sessions.get(session_id)
    if label is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return label.summary()


@router.post("/sessions/{session_id}/close")
def close_session(session_id: str):
    label = flow_engine.sessions.close(session_id)
    if label is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return label.summary()


@router.get("/manifests")
def list_manifests():
    return {"manifests": [_manifest_dict(m) for m in flow_engine.manifests.list()]}


@router.post("/manifests")
def upsert_manifest(body: ManifestUpsert):
    manifest = flow_engine.manifests.register(ToolManifest(
        tool=body.tool,
        action=body.action,
        capabilities=frozenset(body.capabilities),
        destination_field=body.destination_field,
        readers=frozenset(body.readers),
        readers_from=tuple(body.readers_from),
    ))
    return _manifest_dict(manifest)


@router.get("/destinations")
def list_destinations():
    return {"destinations": [{"pattern": r.pattern, "audience": sorted(r.audience)}
                             for r in flow_engine.destinations.rules]}


@router.post("/destinations")
def upsert_destination(body: DestinationUpsert):
    rule = flow_engine.destinations.register(body.pattern, set(body.audience))
    return {"pattern": rule.pattern, "audience": sorted(rule.audience)}


@router.post("/check-output")
def check_rendered_output(body: OutputCheckRequest):
    """Call before rendering a model reply. Returns the text with leaking URLs neutralised."""
    if agent_registry.get(body.agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        result = check_output(flow_engine, body.agent_id, body.session_id, body.text)
    except FlowStateUnavailable as exc:
        raise HTTPException(status_code=503, detail="Session labels unavailable; do not render this output") from exc
    if result is None:
        raise HTTPException(status_code=409, detail="Session does not exist, is closed, or belongs to another agent")
    event_id = None
    if result.sanitised:
        event = audit_ledger.append(
            agent_id=body.agent_id, action="render_output", target=", ".join(sorted({r.host for r in result.removed})),
            decision=Decision.BLOCK.value, risk_score=100, reason=f"Removed {len(result.removed)} URL(s) that could leak data.",
            risk_factors=["rendered-url-egress"], data_findings=[f"lineage:{e['source_event_id']}" for r in result.removed for e in r.lineage],
            policy_version=settings.policy_version, event_type="output.check",
        )
        event_id = event.event_id
    return {
        "text": result.text,
        "sanitised": result.sanitised,
        "urls_checked": result.urls_checked,
        "removed": [{"url": r.url, "kind": r.kind, "host": r.host, "reason": r.reason, "lineage": r.lineage}
                    for r in result.removed],
        "event_id": event_id,
    }
