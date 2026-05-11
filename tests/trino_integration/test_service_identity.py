"""Tests for the Trino service-identity helpers.

Covers the small public surface area of ``trino_integration.service_identity``:

- ``tenant_alias`` / ``tenant_warehouse_name`` / ``validate_trino_tenant_name``
- ``grant_global_trino_access`` — wires the global IAM user into ``{group}ro``
  and grants the global Polaris principal the ``{group}ro_member`` role.
- ``revoke_global_trino_access`` — symmetric, best-effort.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from service.exceptions import GroupOperationError
from trino_integration.service_identity import (
    grant_global_trino_access,
    revoke_global_trino_access,
    tenant_alias,
    tenant_warehouse_name,
    validate_trino_tenant_name,
)


# === Naming helpers ===


class TestNamingHelpers:
    def test_tenant_alias_lowercases_and_replaces_disallowed_chars(self):
        assert tenant_alias("globalusers") == "globalusers"
        assert tenant_alias("GlobalUsers") == "globalusers"
        assert tenant_alias("team-data") == "team_data"
        assert tenant_alias("Mixed-Case_42") == "mixed_case_42"

    def test_tenant_alias_strips_leading_trailing_underscores(self):
        assert tenant_alias("--abc--") == "abc"

    def test_tenant_warehouse_name(self):
        assert tenant_warehouse_name("globalusers") == "tenant_globalusers"
        assert tenant_warehouse_name("kbase") == "tenant_kbase"

    def test_validate_trino_tenant_name_accepts_normal(self):
        assert validate_trino_tenant_name("globalusers") == "globalusers"

    def test_validate_trino_tenant_name_rejects_ro_suffix(self):
        with pytest.raises(GroupOperationError, match="ro"):
            validate_trino_tenant_name("globaluserro")


# === Grant / revoke helpers ===


@pytest.fixture
def app_state_with_globals():
    """AppState with global Trino service identity env vars populated."""
    return SimpleNamespace(
        trino_global_iam_username="trino_svc",
        trino_global_polaris_principal="trino_svc",
        group_manager=AsyncMock(
            add_user_to_group=AsyncMock(),
            remove_user_from_group=AsyncMock(),
        ),
        polaris_service=AsyncMock(
            grant_principal_role_to_principal=AsyncMock(),
            revoke_principal_role_from_principal=AsyncMock(),
        ),
    )


@pytest.fixture
def app_state_without_globals():
    """AppState with both Trino-global env vars unset (test/local-dev case)."""
    return SimpleNamespace(
        trino_global_iam_username="",
        trino_global_polaris_principal="",
        group_manager=AsyncMock(
            add_user_to_group=AsyncMock(),
            remove_user_from_group=AsyncMock(),
        ),
        polaris_service=AsyncMock(
            grant_principal_role_to_principal=AsyncMock(),
            revoke_principal_role_from_principal=AsyncMock(),
        ),
    )


class TestGrantGlobalTrinoAccess:
    @pytest.mark.asyncio
    async def test_adds_iam_user_to_ro_group(self, app_state_with_globals):
        await grant_global_trino_access("globalusers", app_state=app_state_with_globals)
        app_state_with_globals.group_manager.add_user_to_group.assert_awaited_once_with(
            "trino_svc", "globalusersro"
        )

    @pytest.mark.asyncio
    async def test_grants_polaris_reader_role(self, app_state_with_globals):
        await grant_global_trino_access("globalusers", app_state=app_state_with_globals)
        call_kwargs = app_state_with_globals.polaris_service.grant_principal_role_to_principal.call_args.kwargs
        assert call_kwargs["principal"] == "trino_svc"
        # tenant_reader_principal_role("globalusers") -> "globalusersro_member"
        assert "globalusers" in call_kwargs["principal_role"]
        assert "ro_member" in call_kwargs["principal_role"]

    @pytest.mark.asyncio
    async def test_skips_iam_step_when_env_unset(self, app_state_without_globals):
        await grant_global_trino_access(
            "globalusers", app_state=app_state_without_globals
        )
        app_state_without_globals.group_manager.add_user_to_group.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_polaris_step_when_env_unset(self, app_state_without_globals):
        await grant_global_trino_access(
            "globalusers", app_state=app_state_without_globals
        )
        (
            app_state_without_globals.polaris_service.grant_principal_role_to_principal.assert_not_awaited()
        )

    @pytest.mark.asyncio
    async def test_rejects_invalid_tenant_name(self, app_state_with_globals):
        with pytest.raises(GroupOperationError):
            await grant_global_trino_access("groupro", app_state=app_state_with_globals)


class TestRevokeGlobalTrinoAccess:
    @pytest.mark.asyncio
    async def test_revokes_polaris_role_and_removes_from_group(
        self, app_state_with_globals
    ):
        await revoke_global_trino_access(
            "globalusers", app_state=app_state_with_globals
        )
        (
            app_state_with_globals.polaris_service.revoke_principal_role_from_principal.assert_awaited_once()
        )
        app_state_with_globals.group_manager.remove_user_from_group.assert_awaited_once_with(
            "trino_svc", "globalusersro"
        )

    @pytest.mark.asyncio
    async def test_continues_when_polaris_revoke_fails(self, app_state_with_globals):
        # Polaris-side revoke failure must not block the IAM-side removal —
        # a stuck Polaris call would otherwise leak the global IAM user in
        # the {group}ro IAM group on tenant deletion.
        (
            app_state_with_globals.polaris_service.revoke_principal_role_from_principal.side_effect
        ) = Exception("polaris transient")

        await revoke_global_trino_access(
            "globalusers", app_state=app_state_with_globals
        )

        app_state_with_globals.group_manager.remove_user_from_group.assert_awaited_once_with(
            "trino_svc", "globalusersro"
        )

    @pytest.mark.asyncio
    async def test_continues_when_iam_remove_fails(self, app_state_with_globals):
        # IAM-side failure must not raise — symmetric to the polaris case.
        (
            app_state_with_globals.group_manager.remove_user_from_group.side_effect
        ) = Exception("iam transient")

        # Should not raise.
        await revoke_global_trino_access(
            "globalusers", app_state=app_state_with_globals
        )

        # Polaris-side step still ran.
        (
            app_state_with_globals.polaris_service.revoke_principal_role_from_principal.assert_awaited_once()
        )

    @pytest.mark.asyncio
    async def test_skips_when_env_unset(self, app_state_without_globals):
        await revoke_global_trino_access(
            "globalusers", app_state=app_state_without_globals
        )
        (
            app_state_without_globals.polaris_service.revoke_principal_role_from_principal.assert_not_awaited()
        )
        app_state_without_globals.group_manager.remove_user_from_group.assert_not_awaited()
