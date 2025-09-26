"""Software-only simulation / demo - no real systems will be contacted or modified."""
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
    vt_api_key: str | None = Field(default=None, env="VT_API_KEY")
    otx_api_key: str | None = Field(default=None, env="OTX_API_KEY")
    abuse_api_key: str | None = Field(default=None, env="ABUSE_API_KEY")
    request_timeout_seconds: float = 5.0
    request_max_retries: int = 2
    rate_limit_per_minute: int = 30
    uploads_path: str = Field(default="backend/uploads/pcaps", env="UPLOADS_PATH")
    pcap_max_size_mb: int = Field(default=50, env="PCAP_MAX_SIZE_MB")
    ti_cache_ttl_seconds: int = Field(default=300, env="TI_CACHE_TTL_SECONDS")
    enable_dns_resolve: bool = Field(default=False, env="ENABLE_DNS_RESOLVE")
    debug_ti: bool = Field(default=False, env="DEBUG_TI")
    smtp_server: str | None = Field(default=None, env="SMTP_SERVER")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_user: str | None = Field(default=None, env="SMTP_USER")
    smtp_pass: str | None = Field(default=None, env="SMTP_PASS")
    alert_email_from: str | None = Field(default=None, env="ALERT_EMAIL_FROM")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
