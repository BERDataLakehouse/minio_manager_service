"""Tests for the config module."""

import logging
from unittest.mock import patch

from src.service.config import Settings, configure_logging, get_settings


def test_config_imports():
    """Test that config module can be imported."""
    from src.service import config

    assert config is not None


def test_settings_class():
    """Test Settings class can be instantiated."""
    settings = Settings()
    assert settings is not None


def test_get_settings():
    """Test get_settings function."""
    settings = get_settings()
    assert settings is not None


def test_configure_logging():
    """Test configure_logging function with valid level."""
    configure_logging()
    assert True


def test_configure_logging_unrecognized_level(caplog):
    """Test configure_logging warns on unrecognized log level (covers line 54)."""
    bad_settings = Settings(log_level="BOGUS_LEVEL")
    with patch("src.service.config.get_settings", return_value=bad_settings):
        with caplog.at_level(logging.WARNING):
            configure_logging()
    assert "Unrecognized log level" in caplog.text
    assert "BOGUS_LEVEL" in caplog.text
