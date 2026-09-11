from __future__ import annotations

import os
from typing import Any

from supabase import Client, create_client


class SupabaseStore:
    """Server-side persistence adapter using the Supabase service key.

    The service key is read only from the runtime environment and is never
    stored in the repository. When credentials are absent, the adapter is
    disabled so local unit tests remain zero-config.
    """

    def __init__(self, client: Client) -> None:
        self.client = client

    @classmethod
    def from_env(cls) -> "SupabaseStore | None":
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_KEY")
        if not url or not key:
            return None
        return cls(create_client(url, key))

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
            }
        ).execute()

    def healthcheck(self) -> bool:
        self.client.table("security_events").select("event_id").limit(1).execute()
        return True
