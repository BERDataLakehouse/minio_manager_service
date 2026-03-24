"""Tests for the dependencies module."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from src.service.dependencies import require_admin, require_steward_or_admin
from src.service.kb_auth import AdminPermission, KBaseUser


class TestRequireAdmin:
    """Tests for the require_admin dependency."""

    def test_admin_user_passes(self):
        """Test admin user passes the check."""
        admin = KBaseUser(user="admin", admin_perm=AdminPermission.FULL)
        result = require_admin(admin)
        assert result is admin

    def test_non_admin_raises_403(self):
        """Test non-admin user raises 403."""
        user = KBaseUser(user="testuser", admin_perm=AdminPermission.NONE)
        with pytest.raises(HTTPException) as exc_info:
            require_admin(user)
        assert exc_info.value.status_code == 403
        assert "Administrator privileges required" in exc_info.value.detail


class TestRequireStewardOrAdmin:
    """Tests for the require_steward_or_admin helper."""

    def _make_request(self, is_steward: bool = False):
        """Build a mock Request with app_state wired up."""
        mock_metadata_store = MagicMock()
        mock_metadata_store.is_steward = AsyncMock(return_value=is_steward)

        mock_tenant_manager = MagicMock()
        mock_tenant_manager.metadata_store = mock_metadata_store

        mock_app_state = MagicMock()
        mock_app_state.tenant_manager = mock_tenant_manager

        request = MagicMock()
        request.app.state._minio_manager_state = mock_app_state
        return request, mock_metadata_store

    @pytest.mark.asyncio
    async def test_admin_passes_without_steward_check(self):
        admin = KBaseUser(user="admin", admin_perm=AdminPermission.FULL)
        request, mock_store = self._make_request()

        await require_steward_or_admin("tenant1", request, admin)
        mock_store.is_steward.assert_not_called()

    @pytest.mark.asyncio
    async def test_steward_passes(self):
        user = KBaseUser(user="alice", admin_perm=AdminPermission.NONE)
        request, mock_store = self._make_request(is_steward=True)

        await require_steward_or_admin("tenant1", request, user)
        mock_store.is_steward.assert_called_once_with("tenant1", "alice")

    @pytest.mark.asyncio
    async def test_non_admin_non_steward_raises_403(self):
        user = KBaseUser(user="bob", admin_perm=AdminPermission.NONE)
        request, mock_store = self._make_request(is_steward=False)

        with pytest.raises(HTTPException) as exc_info:
            await require_steward_or_admin("tenant1", request, user)
        assert exc_info.value.status_code == 403
        assert "steward" in exc_info.value.detail
