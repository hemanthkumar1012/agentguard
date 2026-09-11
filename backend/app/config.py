from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "AgentGuard API"
    environment: str = "development"


settings = Settings()
