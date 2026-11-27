import os

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


class Settings(BaseModel):
    app_name: str = os.getenv("AGENTGUARD_APP_NAME", "AgentGuard API")
    environment: str = os.getenv("AGENTGUARD_ENV", "development")
    cors_origins: str = os.getenv("AGENTGUARD_CORS_ORIGINS", "http://localhost:3000")
    policy_version: str = os.getenv("AGENTGUARD_POLICY_VERSION", "2026.09")
    api_key: str | None = os.getenv("AGENTGUARD_API_KEY")
    operators: str | None = os.getenv("AGENTGUARD_OPERATORS")
    supabase_url: str | None = os.getenv("SUPABASE_URL")
    supabase_service_key: str | None = os.getenv("SUPABASE_SERVICE_KEY")
    # optional OPA server, e.g. http://localhost:8181; empty means the Python policy is used
    opa_url: str | None = os.getenv("AGENTGUARD_OPA_URL") or None
    # data-flow rules: enforce (default), monitor (record what would happen, change nothing) or off
    flow_mode: str = os.getenv("AGENTGUARD_FLOW_MODE", "enforce").strip().lower()
    # shared session labels for several workers, e.g. redis://localhost:6379/0; empty = process memory
    flow_redis_url: str | None = os.getenv("AGENTGUARD_FLOW_REDIS_URL") or None
    flow_session_ttl_seconds: int = Field(default_factory=lambda: int(os.getenv("AGENTGUARD_FLOW_SESSION_TTL", "86400")), ge=60)
    rate_limit_requests: int = Field(default_factory=lambda: int(os.getenv("AGENTGUARD_RATE_LIMIT", "120")), ge=1)
    rate_limit_window_seconds: int = Field(default_factory=lambda: int(os.getenv("AGENTGUARD_RATE_LIMIT_WINDOW", "60")), ge=1)

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_key)

    @property
    def operator_credentials(self):
        from app.operator_auth import parse_operator_keys
        return parse_operator_keys(self.operators, self.api_key)


settings = Settings()
