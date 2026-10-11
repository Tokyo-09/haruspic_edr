from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SPIRE_", env_file=".env", extra="ignore")

    enrollment_token: str
    admin_token: str
    database_url: str = "sqlite:///./data/spire.db"
    updates_dir: str = "./data/updates"
    host: str = "127.0.0.1"
    port: int = 8080
    max_request_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    max_concurrent_requests: int = Field(default=16, ge=1, le=128)

    @model_validator(mode="after")
    def validate_secrets(self):
        for token in (self.enrollment_token, self.admin_token):
            if len(token) < 32 or token.startswith("dev-"):
                raise ValueError("Configure independent random tokens of at least 32 characters")
        if self.enrollment_token == self.admin_token:
            raise ValueError("Admin and enrollment tokens must differ")
        return self


settings = Settings()
