from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    GITHUB_EVENTS_API_URL: str = "https://api.github.com/events"
    DATABASE_URL: str = "sqlite+aiosqlite:///data/firewall.db"
    DB_PATH: str = "data/firewall.db"
    DEFAULT_MASK_MODE: str = "PARTIAL_MASK"
    LOG_LEVEL: str = "INFO"
    REQUEST_TIMEOUT_SECONDS: float = 15.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def sqlite_path(self) -> Path:
        return Path(self.DB_PATH)


settings = Settings()
