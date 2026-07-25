from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///nyx.db"
    PROXY_HOST: str = "0.0.0.0"
    PROXY_PORT: int = 8080
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    COLLABORATOR_URL: str = "http://localhost:9999"
    COLLABORATOR_DOMAIN: str = "localhost"
    MAX_BODY_SIZE_BYTES: int = 10 * 1024 * 1024
    DEFAULT_SESSION_NAME: str = "Default Session"
    SECRET_KEY: str = ""
    PROXY_MODE: str = "both"
    DEBUG: bool = False

    model_config = {"env_file": str(Path(__file__).resolve().parent.parent.parent / ".env"), "extra": "ignore"}

    @property
    def secret_key(self) -> str:
        if not self.SECRET_KEY:
            import secrets
            self.SECRET_KEY = secrets.token_hex(32)
        return self.SECRET_KEY


settings = Settings()
