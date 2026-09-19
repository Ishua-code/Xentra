from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "XENTRA"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"

    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_request_timeout: int = 10

    class Config:
        env_file = ".env"


settings = Settings()