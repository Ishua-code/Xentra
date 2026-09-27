from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "XENTRA"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "postgresql+asyncpg://xentra:xentra@localhost:5432/xentra"

    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_request_timeout: int = 10

    risk_threshold_critical: float = 0.8
    risk_threshold_high: float = 0.5

    # BloodHound integration (mock-by-default)
    bloodhound_enabled: bool = False
    bloodhound_mock_export_path: str = "app/data/sample_bloodhound_export.json"

    # TheHive integration (mock-by-default)
    thehive_enabled: bool = False
    thehive_api_url: str = "http://localhost:9000/api/v1"
    thehive_api_key: str = ""
    thehive_request_timeout: int = 10

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()