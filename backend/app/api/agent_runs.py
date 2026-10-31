from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.agent_runtime import SAFE_BEHAVIOR, SUPPORT_PERMISSIONS, AgentVersion
from app.services import agent_runner, agent_versions, evaluation_engine

router = APIRouter(tags=["agent-runtime"])


class CreateVersionRequest(BaseModel):
    version_id: str = Field(min_length=3, max_length=60, pattern=r"^[a-z0-9][a-z0-9.\-]+$")
    agent_name: str = Field(default="support-agent", min_length=1, max_length=60)
    description: str = Field(default="", max_length=500)
    model: str = Field(default="gpt-4o-mini", max_length=60)
    prompt_version: str = Field(default="support-prompt-v1", max_length=60)
    system_prompt: str | None = Field(default=None, max_length=8000)
    planner: str = Field(default="scripted", pattern=r"^(scripted|openai)$")
    permissions: list[str] = Field(default_factory=lambda: list(SUPPORT_PERMISSIONS))
    behavior: dict = Field(default_factory=dict)


class RunRequest(BaseModel):
    version_id: str | None = Field(default=None, max_length=60)
    agent_name: str = Field(default="support-agent", max_length=60)
    message: str = Field(min_length=1, max_length=4000)
    tenant_id: str = Field(default="acmepay", min_length=1, max_length=100)
    user_id: str | None = Field(default=None, max_length=100)
    user_role: str = Field(default="customer", max_length=50)


@router.get("/agent-versions")
def list_versions():
    return {"versions": [v.public() for v in agent_versions.list()]}


@router.post("/agent-versions", status_code=201)
def create_version(request: CreateVersionRequest):
    unknown_flags = set(request.behavior) - set(SAFE_BEHAVIOR)
    if unknown_flags:
        raise HTTPException(status_code=422, detail=f"Unknown behavior flags: {sorted(unknown_flags)}")
    unknown_tools = set(request.permissions) - set(SUPPORT_PERMISSIONS)
    if unknown_tools:
        raise HTTPException(status_code=422, detail=f"Unknown tools: {sorted(unknown_tools)}")
    data = request.model_dump(exclude_none=True)
    data["behavior"] = {**SAFE_BEHAVIOR, **request.behavior}
    try:
        version = agent_versions.add(AgentVersion(**data))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return version.public()


@router.get("/agent-versions/{version_id}")
def get_version(version_id: str):
    version = agent_versions.get(version_id)
    if version is None:
        raise HTTPException(status_code=404, detail="Agent version not found")
    return version.public()


@router.post("/agent-versions/{version_id}/promote")
def promote_version(version_id: str):
    try:
        return evaluation_engine.promote(version_id).public()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/runs", status_code=201)
def run_agent(request: RunRequest):
    version_id = request.version_id
    if version_id is None:
        released = agent_versions.released(request.agent_name)
        if released is None:
            raise HTTPException(status_code=404, detail="No released version for this agent")
        version_id = released.version_id
    try:
        return agent_runner.run(version_id, request.message, request.tenant_id, request.user_id,
                                request.user_role).to_dict()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    result = agent_runner.get(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return result.to_dict()


@router.post("/runs/{run_id}/resume")
def resume_run(run_id: str):
    """Continue a run after its pending approval was decided (re-checked by the gateway)."""
    try:
        return agent_runner.resume(run_id).to_dict()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
