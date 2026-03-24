"""Tests for the main application."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.main import create_application
from src.service.kb_auth import AdminPermission, KBaseUser


# ── Health check ──────────────────────────────────────────────────────────


def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


# ── AuthMiddleware ────────────────────────────────────────────────────────


class TestAuthMiddleware:
    def _make_app(self):
        """Build a minimal FastAPI app with AuthMiddleware wired up."""
        app = create_application()

        mock_auth = AsyncMock()
        mock_app_state = MagicMock()
        mock_app_state.auth = mock_auth
        app.state._minio_manager_state = mock_app_state

        return app, mock_auth

    def test_no_auth_header_sets_user_none(self):
        app, mock_auth = self._make_app()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/health")
        assert response.status_code == 200
        mock_auth.get_user.assert_not_called()

    def test_valid_bearer_token_authenticates(self):
        app, mock_auth = self._make_app()
        mock_auth.get_user.return_value = KBaseUser(
            user="alice", admin_perm=AdminPermission.NONE
        )
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get(
            "/health", headers={"Authorization": "Bearer valid-token"}
        )
        assert response.status_code == 200
        mock_auth.get_user.assert_called_once_with("valid-token")

    def test_wrong_scheme_raises(self):
        app, _ = self._make_app()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get(
            "/health", headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        # InvalidAuthHeaderError → 401 via error_mapping + universal_error_handler
        assert response.status_code == 401

    def test_scheme_only_no_credentials_raises(self):
        app, _ = self._make_app()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/health", headers={"Authorization": ""})
        # Empty header — no scheme/creds, so user is None (no error raised)
        # get_authorization_scheme_param returns ("", "") for empty string
        assert response.status_code == 200


# ── create_application ────────────────────────────────────────────────────


class TestCreateApplication:
    def test_returns_fastapi_instance(self):
        app = create_application()
        assert isinstance(app, FastAPI)

    def test_includes_tenant_router(self):
        app = create_application()
        paths = [route.path for route in app.routes]
        assert any("/tenants" in p for p in paths)

    def test_includes_health_router(self):
        app = create_application()
        paths = [route.path for route in app.routes]
        assert "/health" in paths


# ── Startup / Shutdown events ─────────────────────────────────────────────


class TestLifecycleEvents:
    @pytest.mark.asyncio
    async def test_startup_calls_build_app(self):
        app = create_application()
        with patch(
            "src.main.app_state.build_app", new_callable=AsyncMock
        ) as mock_build:
            # Exercise the lifespan context manager (startup phase)
            ctx = app.router.lifespan_context(app)
            await ctx.__aenter__()
            mock_build.assert_called_once_with(app)
            with patch("src.main.app_state.destroy_app_state", new_callable=AsyncMock):
                await ctx.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_shutdown_calls_destroy_app_state(self):
        app = create_application()
        with patch("src.main.app_state.build_app", new_callable=AsyncMock):
            ctx = app.router.lifespan_context(app)
            await ctx.__aenter__()
            with patch(
                "src.main.app_state.destroy_app_state", new_callable=AsyncMock
            ) as mock_destroy:
                await ctx.__aexit__(None, None, None)
                mock_destroy.assert_called_once_with(app)
