"""Tests for PolarisUserManager."""

from unittest.mock import AsyncMock

import pytest

from polaris.managers.user_manager import PolarisUserManager
from service.exceptions import PolarisOperationError


@pytest.fixture
def polaris_service():
    """Mock PolarisService whose safe_delete actually awaits its action.

    Default: get_principal_roles_for_principal returns [] so delete_user's
    defensive revoke loop is a no-op unless a test sets it explicitly.
    """
    svc = AsyncMock()
    svc.get_principal_roles_for_principal = AsyncMock(return_value=[])

    async def _safe_delete(description, action):
        # Real safe_delete swallows PolarisOperationError; mimic that here so
        # tests can wire side_effect on the underlying delete_* methods.
        try:
            await action
        except PolarisOperationError:
            # Intentional no-op: the production safe_delete logs and
            # continues. We mirror the swallow so per-step failures in
            # delete_user tests don't propagate, exactly like prod.
            return

    svc.safe_delete = AsyncMock(side_effect=_safe_delete)
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
        """Delete principal_role → principal → drop_catalog (reverse of create order).

        ``drop_catalog`` (not ``delete_catalog``) is used so the personal
        catalog's namespaces and the ``catalog_admin`` role are emptied
        first. Otherwise Polaris would 4xx and ``safe_delete`` would
        silently leave the catalog orphaned.
        """
        call_order = []
        polaris_service.delete_principal_role.side_effect = lambda *a, **k: (
            call_order.append("role") or None
        )
        polaris_service.delete_principal.side_effect = lambda *a, **k: (
            call_order.append("principal") or None
        )
        polaris_service.drop_catalog.side_effect = lambda *a, **k: (
            call_order.append("catalog") or None
        )

        await manager.delete_user("alice")

        polaris_service.delete_principal_role.assert_called_once_with("alice_role")
        polaris_service.delete_principal.assert_called_once_with("alice")
        polaris_service.drop_catalog.assert_called_once_with("user_alice")
        # delete_catalog is intentionally NOT called directly — drop_catalog
        # is the only correct teardown for a non-empty personal catalog.
        polaris_service.delete_catalog.assert_not_called()
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
        polaris_service.drop_catalog.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_user_continues_after_principal_failure(
        self, manager, polaris_service
    ):
        """Failure on principal delete doesn't block drop_catalog."""
        polaris_service.delete_principal.side_effect = PolarisOperationError(
            "no", status=500
        )

        await manager.delete_user("alice")

        polaris_service.drop_catalog.assert_called_once_with("user_alice")

    @pytest.mark.asyncio
    async def test_delete_user_continues_after_catalog_failure(
        self, manager, polaris_service
    ):
        """A drop_catalog failure is logged and swallowed."""
        polaris_service.drop_catalog.side_effect = PolarisOperationError(
            "no", status=500
        )

        # Should NOT raise — drop_catalog itself is best-effort, but even an
        # outright failure of the call must not propagate.
        await manager.delete_user("alice")

    @pytest.mark.asyncio
    async def test_delete_user_drops_catalog_with_full_cleanup(
        self, manager, polaris_service
    ):
        """delete_user delegates to drop_catalog so namespaces + roles are emptied first.

        Regression guard for the production hazard where the personal
        catalog still contained the ``catalog_admin`` role (and
        potentially user-created tables/namespaces), causing
        ``DELETE /catalogs/user_alice`` to fail and leaving the catalog
        orphaned forever.
        """
        await manager.delete_user("alice")

        polaris_service.drop_catalog.assert_called_once_with("user_alice")
        polaris_service.delete_catalog.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_user_revokes_tenant_role_bindings_first(
        self, manager, polaris_service
    ):
        """Tenant role bindings are revoked before delete_principal.

        Defensive: avoids orphan bindings if the configured Polaris version
        doesn't auto-cascade on delete_principal.
        """
        polaris_service.get_principal_roles_for_principal.return_value = [
            "team1_member",
            "team2ro_member",
            "alice_role",  # personal role appears here too — fine
        ]

        await manager.delete_user("alice")

        # Each tenant role binding got revoked (and the personal one too —
        # the role itself is dropped by delete_principal_role afterwards).
        revoke_calls = (
            polaris_service.revoke_principal_role_from_principal.call_args_list
        )
        assert [c.args for c in revoke_calls] == [
            ("alice", "team1_member"),
            ("alice", "team2ro_member"),
            ("alice", "alice_role"),
        ]
        # Then the standard cleanup runs.
        polaris_service.delete_principal_role.assert_called_once_with("alice_role")
        polaris_service.delete_principal.assert_called_once_with("alice")
        polaris_service.drop_catalog.assert_called_once_with("user_alice")

    @pytest.mark.asyncio
    async def test_delete_user_continues_when_listing_bindings_fails(
        self, manager, polaris_service
    ):
        """If we can't list bindings, fall back to delete-and-hope-it-cascades."""
        polaris_service.get_principal_roles_for_principal.side_effect = (
            PolarisOperationError("forbidden", status=403)
        )

        # Should NOT raise; cleanup still runs without the defensive revoke.
        await manager.delete_user("alice")

        polaris_service.revoke_principal_role_from_principal.assert_not_called()
        polaris_service.delete_principal_role.assert_called_once_with("alice_role")
        polaris_service.delete_principal.assert_called_once_with("alice")
        polaris_service.drop_catalog.assert_called_once_with("user_alice")

    @pytest.mark.asyncio
    async def test_delete_user_continues_after_individual_revoke_failure(
        self, manager, polaris_service
    ):
        """One failed revoke doesn't block the remaining revokes or the
        downstream principal/catalog delete."""
        polaris_service.get_principal_roles_for_principal.return_value = [
            "team1_member",
            "team2_member",
        ]
        polaris_service.revoke_principal_role_from_principal.side_effect = [
            PolarisOperationError("boom", status=500),
            None,
        ]

        await manager.delete_user("alice")

        assert polaris_service.revoke_principal_role_from_principal.call_count == 2
        polaris_service.delete_principal.assert_called_once()
        polaris_service.drop_catalog.assert_called_once()
