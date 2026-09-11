import os

from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()


class Settings(BaseModel):
    app_name: str = os.getenv("AGENTGUARD_APP_NAME", "AgentGuard API")
    environment: str = os.getenv("AGENTGUARD_ENV", "development")
    cors_origins: str = os.getenv("AGENTGUARD_CORS_ORIGINS", "http://localhost:3000")
    policy_version: str = os.getenv("AGENTGUARD_POLICY_VERSION", "2026.09")
    api_key: str | None = os.getenv("AGENTGUARD_API_KEY")
    supabase_url: str | None = os.getenv("SUPABASE_URL")
    supabase_service_key: str | None = os.getenv("SUPABASE_SERVICE_KEY")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_key)


settings = Settings()
