from typing import List, Literal
from pydantic import AnyHttpUrl, SecretStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Project Metadata
    PROJECT_NAME: str = "Sentinel-Sim"
    PROJECT_VERSION: str = "0.1.0"
    PROJECT_DESCRIPTION: str = "Production-inspired SIEM Alert Dashboard & Simulator"
    
    # Environment Configuration
    ENVIRONMENT: Literal["local", "development", "staging", "production"] = "production"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: SecretStr = Field(..., description="JWT signing secret")
    ALGORITHM: str = "HS256"
    
    # Infrastructure
    ELASTICSEARCH_URL: AnyHttpUrl = Field(...)
    ELASTICSEARCH_USER: str = "elastic"
    ELASTICSEARCH_PASSWORD: SecretStr = Field(...)

    # CORS
    ALLOWED_ORIGINS: List[AnyHttpUrl] = []

    @property
    def is_dev(self) -> bool:
        return self.ENVIRONMENT in ("local", "development")

settings = Settings()