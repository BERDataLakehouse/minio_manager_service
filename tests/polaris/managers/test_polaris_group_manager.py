"""Tests for PolarisGroupManager."""

from unittest.mock import AsyncMock, call

import pytest

from polaris.managers.group_manager import PolarisGroupManager
from service.exceptions import PolarisOperationError


@pytest.fixture
def polaris_service():
    return AsyncMock()


@pytest.fixture
def manager(polaris_service):
    return PolarisGroupManager(
        polaris_service=polaris_service,
        tenant_sql_warehouse_base="s3a://cdm-lake/tenant-sql-warehouse",
    )


# === ensure_catalog ===


class TestEnsureCatalog:
    @pytest.mark.asyncio
    async def test_ensure_catalog_calls_polaris_service(self, manager, polaris_service):
        await manager.ensure_catalog("teamA")

        polaris_service.ensure_tenant_catalog.assert_called_once_with(
            "teamA", "s3a://cdm-lake/tenant-sql-warehouse/teamA/iceberg/"
        )

    @pytest.mark.asyncio
    async def test_ensure_catalog_uses_configured_warehouse_base(self, polaris_service):
        manager = PolarisGroupManager(
            polaris_service=polaris_service,
            tenant_sql_warehouse_base="s3a://other/wh",
        )
        await manager.ensure_catalog("teamA")

        polaris_service.ensure_tenant_catalog.assert_called_once_with(
            "teamA", "s3a://other/wh/teamA/iceberg/"
        )


# === create_group ===


class TestCreateGroup:
    @pytest.mark.asyncio
    async def test_create_group_provisions_catalog_then_binds_creator_to_both_roles(
        self, manager, polaris_service
    ):
        """Creator gets both writer (base) and reader ({group}ro) bindings."""
        await manager.create_group("teamA", creator="admin")

        # ensure_tenant_catalog is called redundantly (3×): once explicitly
        # via ensure_catalog and once inside each add_user_to_group call.
        # PolarisService check-first makes the extra calls cheap; we keep
        # add_user_to_group self-healing so backfill / legacy flows work.
        # Assert every call targeted the right base storage location.
        ensure_calls = polaris_service.ensure_tenant_catalog.call_args_list
        expected_call = call(
            "teamA", "s3a://cdm-lake/tenant-sql-warehouse/teamA/iceberg/"
        )
        assert all(c == expected_call for c in ensure_calls)
        assert len(ensure_calls) >= 1

        # Both writer and reader role grants for the creator.
        grant_calls = polaris_service.grant_principal_role_to_principal.call_args_list
        assert call("admin", "teamA_member") in grant_calls
        assert call("admin", "teamAro_member") in grant_calls
        assert len(grant_calls) == 2


# === delete_group ===


class TestDeleteGroup:
    @pytest.mark.asyncio
    async def test_delete_base_group_drops_catalog(self, manager, polaris_service):
        await manager.delete_group("teamA")

        polaris_service.drop_tenant_catalog.assert_called_once_with("teamA")

    @pytest.mark.asyncio
    async def test_delete_ro_group_is_noop(self, manager, polaris_service):
        """{group}ro inputs don't have their own catalog — no-op."""
        await manager.delete_group("teamAro")

        polaris_service.drop_tenant_catalog.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_empty_base_is_noop(self, manager, polaris_service):
        """Empty base name (group named exactly "ro") is treated as no-op."""
        await manager.delete_group("ro")

        polaris_service.drop_tenant_catalog.assert_not_called()


# === add_user_to_group ===


class TestAddUserToGroup:
    @pytest.mark.asyncio
    async def test_add_to_base_group_grants_writer_role(self, manager, polaris_service):
        await manager.add_user_to_group("alice", "teamA")

        polaris_service.ensure_tenant_catalog.assert_called_once_with(
            "teamA", "s3a://cdm-lake/tenant-sql-warehouse/teamA/iceberg/"
        )
        polaris_service.create_principal.assert_called_once_with(name="alice")
        polaris_service.grant_principal_role_to_principal.assert_called_once_with(
            "alice", "teamA_member"
        )

    @pytest.mark.asyncio
    async def test_add_to_ro_group_grants_reader_role_on_base_catalog(
        self, manager, polaris_service
    ):
        """{group}ro maps to {group}ro_member on the BASE catalog."""
        await manager.add_user_to_group("alice", "teamAro")

        polaris_service.ensure_tenant_catalog.assert_called_once_with(
            "teamA", "s3a://cdm-lake/tenant-sql-warehouse/teamA/iceberg/"
        )
        polaris_service.grant_principal_role_to_principal.assert_called_once_with(
            "alice", "teamAro_member"
        )

    @pytest.mark.asyncio
    async def test_add_to_empty_base_is_noop(self, manager, polaris_service):
        """Group named "ro" → empty base → no-op."""
        await manager.add_user_to_group("alice", "ro")

        polaris_service.ensure_tenant_catalog.assert_not_called()
        polaris_service.create_principal.assert_not_called()
        polaris_service.grant_principal_role_to_principal.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_self_heals_for_pre_polaris_groups(
        self, manager, polaris_service
    ):
        """ensure_tenant_catalog and create_principal are always called for safety."""
        await manager.add_user_to_group("alice", "teamA")

        # These two are the "self-healing" calls — verified above by
        # assert_called_once_with — repeated here to make the intent explicit.
        polaris_service.ensure_tenant_catalog.assert_called_once()
        polaris_service.create_principal.assert_called_once()


# === remove_user_from_group ===


class TestRemoveUserFromGroup:
    @pytest.mark.asyncio
    async def test_remove_from_base_group_revokes_writer_role(
        self, manager, polaris_service
    ):
        await manager.remove_user_from_group("alice", "teamA")

        polaris_service.revoke_principal_role_from_principal.assert_called_once_with(
            "alice", "teamA_member"
        )

    @pytest.mark.asyncio
    async def test_remove_from_ro_group_revokes_reader_role(
        self, manager, polaris_service
    ):
        await manager.remove_user_from_group("alice", "teamAro")

        polaris_service.revoke_principal_role_from_principal.assert_called_once_with(
            "alice", "teamAro_member"
        )

    @pytest.mark.asyncio
    async def test_remove_from_empty_base_is_noop(self, manager, polaris_service):
        await manager.remove_user_from_group("alice", "ro")

        polaris_service.revoke_principal_role_from_principal.assert_not_called()

    @pytest.mark.asyncio
    async def test_remove_propagates_non_404_errors(self, manager, polaris_service):
        """PolarisService.revoke is 404-tolerant; non-404 errors propagate."""
        polaris_service.revoke_principal_role_from_principal.side_effect = (
            PolarisOperationError("forbidden", status=403)
        )
        with pytest.raises(PolarisOperationError):
            await manager.remove_user_from_group("alice", "teamA")
