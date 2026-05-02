"""
Configuration settings for the MinIO Manager API.

A centralized FastAPI service to manage MinIO users, groups, and policies for data governance with KBase authentication integration.
"""

import logging
import os
from functools import lru_cache

from pydantic import BaseModel, Field, field_validator

APP_VERSION = "0.1.0"


class Settings(BaseModel):
    """
    Application settings for the MinIO Manager Service.
    """

    app_name: str = "MinIO Manager Service"
    app_description: str = "FastAPI service to manage MinIO users, groups, and policies for data governance with KBase authentication integration"
    api_version: str = APP_VERSION
    service_root_path: str = os.getenv("SERVICE_ROOT_PATH", "")
    log_level: str = Field(
        default=os.getenv("LOG_LEVEL", "INFO"),
        description="Logging level for the application",
    )
    read_cache_ttl_seconds: float = Field(
        default=float(os.getenv("READ_CACHE_TTL_SECONDS", "60.0")),
        description=(
            "TTL (seconds) for per-replica read-side caches that front the "
            "GroupManager and TenantMetadataStore lookups. Bounds staleness "
            "for cross-pod / external mutations; in-pod mutations invalidate "
            "explicitly so this acts only as a backstop."
        ),
    )

    @field_validator("service_root_path", mode="before")
    @classmethod
    def normalize_service_root_path(cls, v: str) -> str:
        """
        Normalize the service root path to either:
        - an empty string (root), or
        - a single-leading-slash prefix with no trailing slash.
        """
        if v is None:
            return ""
        v = str(v).strip()
        # Treat "/" as root (empty string), matching FastAPI/Starlette default behavior.
        if v == "" or v == "/":
            return ""
        if not v.startswith("/"):
            v = "/" + v
        # Remove trailing slash for non-root paths.
        if v.endswith("/") and v != "/":
            v = v.rstrip("/")
        return v


@lru_cache()
def get_settings() -> Settings:
    """
    Get the application settings.

    Uses lru_cache to avoid loading the settings for every request.
    """
    return Settings()


# Global settings instance for convenience
settings = get_settings()


def configure_logging():
    """Configure logging for the application."""
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if settings.log_level.upper() not in logging.getLevelNamesMapping():
        logging.warning(
            "Unrecognized log level '%s'. Falling back to 'INFO'.",
            settings.log_level,
        )
