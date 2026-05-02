"""Tests for PolarisUserManager."""

from unittest.mock import AsyncMock

import pytest

from polaris.managers.user_manager import PolarisUserManager
from service.exceptions import PolarisOperationError


@pytest.fixture
def polaris_service():
    svc = AsyncMock()
    return svc


@pytest.fixture
def manager(polaris_service):
    return PolarisUserManager(
        polaris_service=polaris_service,
        users_sql_warehouse_base="s3a://cdm-lake/users-sql-warehouse",
    )


# === create_user ===


class TestCreateUser:
    @pytest.mark.asyncio
    async def test_create_user_runs_full_provisioning_sequence(
        self, manager, polaris_service
    ):
        """create_user calls catalog → principal → role wiring in order."""
        await manager.create_user("alice")

        polaris_service.create_catalog.assert_called_once_with(
            name="user_alice",
            storage_location="s3a://cdm-lake/users-sql-warehouse/alice/iceberg/",
        )
        polaris_service.create_principal.assert_called_once_with(name="alice")
        polaris_service.create_catalog_role.assert_called_once_with(
            catalog="user_alice", role_name="catalog_admin"
        )
        polaris_service.grant_catalog_privilege.assert_called_once_with(
            catalog="user_alice",
            role_name="catalog_admin",
            privilege="CATALOG_MANAGE_CONTENT",
        )
        polaris_service.create_principal_role.assert_called_once_with(
            role_name="alice_role"
        )
        polaris_service.grant_catalog_role_to_principal_role.assert_called_once_with(
            catalog="user_alice",
            catalog_role="catalog_admin",
            principal_role="alice_role",
        )
        polaris_service.grant_principal_role_to_principal.assert_called_once_with(
            principal="alice", principal_role="alice_role"
        )

    @pytest.mark.asyncio
    async def test_create_user_uses_configured_warehouse_base(self, polaris_service):
        """The catalog storage location respects the constructor's base path."""
        manager = PolarisUserManager(
            polaris_service=polaris_service,
            users_sql_warehouse_base="s3a://other-bucket/some-prefix",
        )
        await manager.create_user("bob")

        polaris_service.create_catalog.assert_called_once_with(
            name="user_bob",
            storage_location="s3a://other-bucket/some-prefix/bob/iceberg/",
        )

    @pytest.mark.asyncio
    async def test_create_user_propagates_errors(self, manager, polaris_service):
        """An error from PolarisService propagates (not best-effort here)."""
        polaris_service.create_catalog.side_effect = PolarisOperationError(
            "boom", status=500
        )
        with pytest.raises(PolarisOperationError):
            await manager.create_user("alice")


# === delete_user ===


class TestDeleteUser:
    @pytest.mark.asyncio
    async def test_delete_user_reverse_creation_order(self, manager, polaris_service):
        """Delete principal_role → principal → catalog (reverse of create order)."""
        # Track call order
        call_order = []
        polaris_service.delete_principal_role.side_effect = lambda *a, **k: (
            call_order.append("role") or None
        )
        polaris_service.delete_principal.side_effect = lambda *a, **k: (
            call_order.append("principal") or None
        )
        polaris_service.delete_catalog.side_effect = lambda *a, **k: (
            call_order.append("catalog") or None
        )

        await manager.delete_user("alice")

        polaris_service.delete_principal_role.assert_called_once_with("alice_role")
        polaris_service.delete_principal.assert_called_once_with("alice")
        polaris_service.delete_catalog.assert_called_once_with("user_alice")
        assert call_order == ["role", "principal", "catalog"]

    @pytest.mark.asyncio
    async def test_delete_user_continues_after_role_failure(
        self, manager, polaris_service
    ):
        """Delete is best-effort — a failure in one step doesn't block later steps."""
        polaris_service.delete_principal_role.side_effect = PolarisOperationError(
            "no", status=500
        )

        # Should NOT raise
        await manager.delete_user("alice")

        polaris_service.delete_principal_role.assert_called_once()
        polaris_service.delete_principal.assert_called_once()
        polaris_service.delete_catalog.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_user_continues_after_principal_failure(
        self, manager, polaris_service
    ):
        """Failure on principal delete doesn't block catalog delete."""
        polaris_service.delete_principal.side_effect = PolarisOperationError(
            "no", status=500
        )

        await manager.delete_user("alice")

        polaris_service.delete_catalog.assert_called_once_with("user_alice")

    @pytest.mark.asyncio
    async def test_delete_user_continues_after_catalog_failure(
        self, manager, polaris_service
    ):
        """A catalog-delete failure is logged and swallowed."""
        polaris_service.delete_catalog.side_effect = PolarisOperationError(
            "no", status=500
        )

        # Should NOT raise
        await manager.delete_user("alice")
