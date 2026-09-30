import secrets
import sys
from typing import List, Optional

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./jocky.db"
    SECRET_KEY: Optional[str] = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    PROJECT_NAME: str = "JOCKY"
    STORAGE_DIR: str = "./storage"
    CORS_ORIGINS: List[str] = ["*"]
    BACKEND_URL: Optional[str] = "http://localhost:8000"
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"

settings = Settings()
if not settings.SECRET_KEY:
    print("[!] WARNING: SECRET_KEY not found in environment. Using a temporary fallback key for development ONLY.", file=sys.stderr)
    settings.SECRET_KEY = secrets.token_urlsafe(32)
