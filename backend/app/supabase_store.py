from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from supabase import Client, create_client


class SupabaseStore:
    """Server-side persistence adapter using the Supabase service key."""

    def __init__(self, client: Client) -> None:
        self.client = client

    @classmethod
    def from_env(cls) -> "SupabaseStore | None":
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_KEY")
        if not url or not key:
            return None
        return cls(create_client(url, key))

    def list_agents(self) -> list[dict[str, Any]]:
        rows = self.client.table("agents").select("id,agent_id,name,owner,environment,status,created_at").execute().data or []
        for row in rows:
            permission_rows = self.client.table("agent_permissions").select("permission").eq("agent_id", row["id"]).execute().data or []
            row["permissions"] = [item["permission"] for item in permission_rows]
        return rows

    def insert_agent(self, agent: Any) -> None:
        self.client.table("agents").insert({
            "agent_id": agent.agent_id, "name": agent.name, "owner": agent.owner,
            "environment": agent.environment, "status": agent.status.value,
            "created_at": agent.created_at.isoformat(),
        }).execute()
        agent_row = self.client.table("agents").select("id").eq("agent_id", agent.agent_id).single().execute().data
        if agent_row and agent.permissions:
            self.client.table("agent_permissions").insert([
                {"agent_id": agent_row["id"], "permission": permission} for permission in agent.permissions
            ]).execute()

    def update_agent_status(self, agent_id: str, status: str) -> None:
        self.client.table("agents").update({"status": status}).eq("agent_id", agent_id).execute()

    def insert_credential(self, credential_id: str, agent_id: str, tool: str, scopes, token_hash: str, expires_at) -> None:
        self.client.table("scoped_credentials").insert({
            "credential_id": credential_id, "agent_id": agent_id, "tool": tool,
            "scopes": list(scopes), "token_hash": token_hash, "expires_at": expires_at.isoformat(),
        }).execute()

    def get_credential(self, credential_id: str) -> dict[str, Any] | None:
        rows = self.client.table("scoped_credentials").select(
            "credential_id,agent_id,tool,scopes,token_hash,expires_at,revoked_at"
        ).eq("credential_id", credential_id).limit(1).execute().data or []
        return rows[0] if rows else None

    def revoke_credential(self, credential_id: str) -> bool:
        response = self.client.table("scoped_credentials").update(
            {"revoked_at": datetime.now(timezone.utc).isoformat()}
        ).eq("credential_id", credential_id).is_("revoked_at", "null").execute()
        return bool(response.data)

    def insert_approval(self, approval: Any) -> None:
        self.client.table("approvals").insert({
            "approval_id": approval.approval_id, "event_id": approval.event_id,
            "requested_by": approval.requested_by, "status": approval.status,
            "decision_note": approval.decision_note, "expires_at": approval.expires_at.isoformat(),
            "decided_by": approval.decided_by,
            "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
        }).execute()

    @staticmethod
    def _approval(row: dict[str, Any]):
        from app.approvals import Approval
        return Approval(
            approval_id=row["approval_id"], event_id=row.get("event_id"), requested_by=row["requested_by"],
            status=row["status"], decision_note=row.get("decision_note"),
            expires_at=datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")),
            decided_by=row.get("decided_by"),
            decided_at=datetime.fromisoformat(row["decided_at"].replace("Z", "+00:00")) if row.get("decided_at") else None,
        )

    def get_approval(self, approval_id: str):
        rows = self.client.table("approvals").select(
            "approval_id,event_id,requested_by,status,decision_note,expires_at,decided_by,decided_at"
        ).eq("approval_id", approval_id).limit(1).execute().data or []
        return self._approval(rows[0]) if rows else None

    def list_approvals(self):
        rows = self.client.table("approvals").select(
            "approval_id,event_id,requested_by,status,decision_note,expires_at,decided_by,decided_at"
        ).order("created_at", desc=True).execute().data or []
        return [self._approval(row) for row in rows]

    def update_approval(self, approval: Any) -> None:
        self.client.table("approvals").update({
            "status": approval.status, "decision_note": approval.decision_note,
            "decided_by": approval.decided_by,
            "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
        }).eq("approval_id", approval.approval_id).execute()

    def get_last_event_hash(self) -> str | None:
        rows = self.client.table("security_events").select("event_hash").order("created_at", desc=True).limit(1).execute().data or []
        return rows[0].get("event_hash") if rows else None

    def insert_security_event(self, event: Any) -> None:
        self.client.table("security_events").insert({
            "event_id": event.event_id, "event_type": event.event_type, "agent_id": event.agent_id,
            "action": event.action, "target": event.target, "tool": event.tool,
            "credential_id": event.credential_id, "correlation_id": event.correlation_id,
            "decision": event.decision, "risk_score": event.risk_score,
            "risk_factors": list(event.risk_factors), "data_findings": list(event.data_findings),
            "reason": event.reason, "policy_version": event.policy_version,
            "created_at": event.created_at.isoformat(), "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
        }).execute()

    def healthcheck(self) -> bool:
        self.client.table("security_events").select("event_id").limit(1).execute()
        return True
