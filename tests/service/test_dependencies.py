"""Tests for the dependencies module."""

import pytest
from fastapi import HTTPException

from src.service.dependencies import require_admin
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
