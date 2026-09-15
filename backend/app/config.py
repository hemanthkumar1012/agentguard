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
    supabase_url: str | None = os.getenv("SUPABASE_URL")
    supabase_service_key: str | None = os.getenv("SUPABASE_SERVICE_KEY")
    rate_limit_requests: int = Field(default_factory=lambda: int(os.getenv("AGENTGUARD_RATE_LIMIT", "120")), ge=1)
    rate_limit_window_seconds: int = Field(default_factory=lambda: int(os.getenv("AGENTGUARD_RATE_LIMIT_WINDOW", "60")), ge=1)

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_key)


settings = Settings()
