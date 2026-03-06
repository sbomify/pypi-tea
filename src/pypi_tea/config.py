from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    redis_url: str = "redis://localhost:6379/0"
    pypi_base_url: str = "https://pypi.org"
    tea_spec_version: str = "0.3.0-beta.2"
    server_root_url: str = "http://localhost:8000"

    model_config = {"env_prefix": "PYPI_TEA_"}


settings = Settings()
