"""Software-only simulation / demo — no real systems will be contacted or modified."""
from functools import lru_cache

from pydantic import AnyUrl, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "EyeGuard"
    database_url: AnyUrl = Field(
        "postgresql+asyncpg://eyeguard:eyeguard@localhost:5432/eyeguard",
        env="DATABASE_URL",
    )
    redis_url: AnyUrl = Field("redis://localhost:6379/0", env="REDIS_URL")
    vt_api_key: str | None = Field(default=None, env="VT_API_KEY50a31e8751e864ded8f13c4a0f8d4da0efcfe214c48dc1303df5a85d82b0eb2f")
    otx_api_key: str | None = Field(default=None, env="26dda8e419d2035313837dad69bc5289cf9ad4f0359523c8ebcf136bb66a9589")
    abuse_api_key: str | None = Field(default=None, env="8a57330f39c078ad2c3c24dda2635d9b2c520d0a36f39c7bbb0fb15a8443ba3b0b1401ba9bfb13aa")
    request_timeout_seconds: float = 5.0
    request_max_retries: int = 2
    rate_limit_per_minute: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
