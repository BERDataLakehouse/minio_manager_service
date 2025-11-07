"""
Configuration settings for the MinIO Manager API.

A centralized FastAPI service to manage MinIO users, groups, and policies for data governance with KBase authentication integration.
"""

import logging
import os
from functools import lru_cache

from pydantic import BaseModel, Field

APP_VERSION = "0.1.0"


class Settings(BaseModel):
    """
    Application settings for the MinIO Manager Service.
    """

    app_name: str = "MinIO Manager Service"
    app_description: str = "FastAPI service to manage MinIO users, groups, and policies for data governance with KBase authentication integration"
    api_version: str = APP_VERSION
    log_level: str = Field(
        default=os.getenv("LOG_LEVEL", "INFO"),
        description="Logging level for the application",
    )


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
