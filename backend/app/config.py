import os

from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = os.getenv("AGENTGUARD_APP_NAME", "AgentGuard API")
    environment: str = os.getenv("AGENTGUARD_ENV", "development")
    cors_origins: str = os.getenv("AGENTGUARD_CORS_ORIGINS", "http://localhost:3000")
    policy_version: str = os.getenv("AGENTGUARD_POLICY_VERSION", "2026.09")
    api_key: str | None = os.getenv("AGENTGUARD_API_KEY")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


settings = Settings()
