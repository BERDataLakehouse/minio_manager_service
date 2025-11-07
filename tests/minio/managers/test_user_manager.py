"""Tests for the minio.managers.user_manager module."""

from src.minio.managers import user_manager


def test_user_manager_imports():
    """Test that user_manager module can be imported."""
    assert user_manager is not None


def test_noop():
    """Simple placeholder test."""
    assert 1 == 1
