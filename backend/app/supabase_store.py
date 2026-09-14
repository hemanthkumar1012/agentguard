from __future__ import annotations

import os
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
            permission_rows = (
                self.client.table("agent_permissions")
                .select("permission")
                .eq("agent_id", row["id"])
                .execute()
                .data
                or []
            )
            row["permissions"] = [item["permission"] for item in permission_rows]
        return rows

    def insert_agent(self, agent: Any) -> None:
        self.client.table("agents").insert(
            {
                "agent_id": agent.agent_id,
                "name": agent.name,
                "owner": agent.owner,
                "environment": agent.environment,
                "status": agent.status.value,
                "created_at": agent.created_at.isoformat(),
            }
        ).execute()
        agent_row = self.client.table("agents").select("id").eq("agent_id", agent.agent_id).single().execute().data
        if agent_row and agent.permissions:
            self.client.table("agent_permissions").insert(
                [{"agent_id": agent_row["id"], "permission": permission} for permission in agent.permissions]
            ).execute()

    def update_agent_status(self, agent_id: str, status: str) -> None:
        self.client.table("agents").update({"status": status}).eq("agent_id", agent_id).execute()

    def insert_security_event(self, event: Any) -> None:
        self.client.table("security_events").insert(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "agent_id": event.agent_id,
                "action": event.action,
                "target": event.target,
                "tool": event.tool,
                "credential_id": event.credential_id,
                "correlation_id": event.correlation_id,
                "decision": event.decision,
                "risk_score": event.risk_score,
                "risk_factors": list(event.risk_factors),
                "data_findings": list(event.data_findings),
                "reason": event.reason,
                "policy_version": event.policy_version,
                "created_at": event.created_at.isoformat(),
                "previous_hash": event.previous_hash,
                "event_hash": event.event_hash,
            }
        ).execute()

    def healthcheck(self) -> bool:
        self.client.table("security_events").select("event_id").limit(1).execute()
        return True
