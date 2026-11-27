"""Operator API for injected credentials. Values go in once and are never returned."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services import secret_vault

router = APIRouter(prefix="/vault", tags=["vault"])


class SecretPut(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=8, max_length=8192, repr=False)
    allowed_destinations: list[str] = Field(min_length=1, max_length=20)
    allowed_agents: list[str] = Field(min_length=1, max_length=100)


@router.post("/secrets", status_code=201)
def put_secret(body: SecretPut):
    try:
        secret = secret_vault.put(body.name, body.value, body.allowed_destinations, body.allowed_agents)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {**secret.metadata(), "handle": "{{secret:%s}}" % secret.name}


@router.get("/secrets")
def list_secrets():
    return {"secrets": secret_vault.list()}


@router.post("/secrets/{name}/revoke")
def revoke_secret(name: str):
    if not secret_vault.revoke(name):
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"name": name, "revoked": True}
