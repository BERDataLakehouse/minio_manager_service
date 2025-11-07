"""Tests for the routes.workspaces module."""

from src.routes import workspaces


def test_workspaces_imports():
    """Test that workspaces module can be imported."""
    assert workspaces is not None


def test_noop():
    """Simple placeholder test."""
    assert 1 == 1
