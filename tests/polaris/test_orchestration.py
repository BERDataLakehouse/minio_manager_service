"""Tests for the polaris.orchestration module."""

from unittest.mock import AsyncMock

import pytest

from polaris.orchestration import ensure_user_polaris_state


@pytest.fixture
def polaris_user_manager():
    return AsyncMock()


@pytest.fixture
def polaris_group_manager():
    return AsyncMock()


@pytest.fixture
def group_manager():
    mgr = AsyncMock()
    mgr.get_user_groups = AsyncMock(return_value=[])
    return mgr


@pytest.fixture
def call_helper(polaris_user_manager, polaris_group_manager, group_manager):
    """Convenience: returns a coroutine factory that fills the manager kwargs."""

    async def _call(username, exclude_groups=None):
        return await ensure_user_polaris_state(
            username,
            polaris_user_manager=polaris_user_manager,
            polaris_group_manager=polaris_group_manager,
            group_manager=group_manager,
            exclude_groups=exclude_groups,
        )

    return _call


class TestEnsureUserPolarisState:
    """Tests for ensure_user_polaris_state."""

    @pytest.mark.asyncio
    async def test_provisions_personal_assets_first(
        self, call_helper, polaris_user_manager
    ):
        """Personal Polaris assets are provisioned before group bindings."""
        await call_helper("alice")

        polaris_user_manager.create_user.assert_called_once_with("alice")

    @pytest.mark.asyncio
    async def test_returns_personal_catalog_name(self, call_helper):
        """Returns the canonical user_<name> catalog name."""
        catalog, tenants = await call_helper("alice")

        assert catalog == "user_alice"
        assert tenants == []

    @pytest.mark.asyncio
    async def test_no_groups_yields_empty_tenant_list(
        self, call_helper, group_manager, polaris_group_manager
    ):
        """User with no MinIO group memberships gets no Polaris bindings."""
        group_manager.get_user_groups.return_value = []

        _, tenants = await call_helper("alice")

        assert tenants == []
        polaris_group_manager.add_user_to_group.assert_not_called()

    @pytest.mark.asyncio
    async def test_mirrors_each_distinct_base_group(
        self, call_helper, group_manager, polaris_group_manager
    ):
        """Distinct base groups each get one add_user_to_group call."""
        group_manager.get_user_groups.return_value = ["teamA", "teamB"]

        _, tenants = await call_helper("alice")

        assert sorted(tenants) == ["tenant_teamA", "tenant_teamB"]
        add_calls = polaris_group_manager.add_user_to_group.call_args_list
        assert sorted(c.args for c in add_calls) == [
            ("alice", "teamA"),
            ("alice", "teamB"),
        ]

    @pytest.mark.asyncio
    async def test_dedups_writer_and_reader_to_writer_only(
        self, call_helper, group_manager, polaris_group_manager
    ):
        """User in both teamA and teamAro gets one writer binding."""
        group_manager.get_user_groups.return_value = ["teamA", "teamAro"]

        _, tenants = await call_helper("alice")

        assert tenants == ["tenant_teamA"]
        polaris_group_manager.add_user_to_group.assert_called_once_with(
            "alice", "teamA"
        )

    @pytest.mark.asyncio
    async def test_ro_only_membership_passes_through_ro_suffix(
        self, call_helper, group_manager, polaris_group_manager
    ):
        """User in only teamAro gets the {group}ro name (not stripped)."""
        group_manager.get_user_groups.return_value = ["teamAro"]

        _, tenants = await call_helper("alice")

        assert tenants == ["tenant_teamA"]
        polaris_group_manager.add_user_to_group.assert_called_once_with(
            "alice", "teamAro"
        )

    @pytest.mark.asyncio
    async def test_exclude_groups_skips_matching_bases(
        self, call_helper, group_manager, polaris_group_manager
    ):
        """exclude_groups drops the base from both the tenant list and the bindings."""
        group_manager.get_user_groups.return_value = ["teamA", "teamB", "teamCro"]

        _, tenants = await call_helper("alice", exclude_groups={"teamB"})

        assert "tenant_teamA" in tenants
        assert "tenant_teamC" in tenants
        assert "tenant_teamB" not in tenants
        add_calls = polaris_group_manager.add_user_to_group.call_args_list
        target_groups = {c.args[1] for c in add_calls}
        assert "teamB" not in target_groups
        assert "teamA" in target_groups
        assert "teamCro" in target_groups

    @pytest.mark.asyncio
    async def test_exclude_groups_skips_ro_sibling_too(
        self, call_helper, group_manager, polaris_group_manager
    ):
        """Excluding base "teamA" also drops "teamAro" bindings (via base lookup)."""
        group_manager.get_user_groups.return_value = ["teamAro"]

        _, tenants = await call_helper("alice", exclude_groups={"teamA"})

        assert tenants == []
        polaris_group_manager.add_user_to_group.assert_not_called()

    @pytest.mark.asyncio
    async def test_personal_assets_provisioned_even_when_excluded_groups_skip_all(
        self,
        call_helper,
        group_manager,
        polaris_user_manager,
        polaris_group_manager,
    ):
        """Even if every group is excluded, personal Polaris assets still happen."""
        group_manager.get_user_groups.return_value = ["teamA"]

        await call_helper("alice", exclude_groups={"teamA"})

        polaris_user_manager.create_user.assert_called_once_with("alice")
        polaris_group_manager.add_user_to_group.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_exclude_groups_default_treats_as_no_exclusion(
        self, call_helper, group_manager, polaris_group_manager
    ):
        """exclude_groups=None and exclude_groups=set() are equivalent."""
        group_manager.get_user_groups.return_value = ["teamA"]

        await call_helper("alice")
        polaris_group_manager.add_user_to_group.assert_called_once_with(
            "alice", "teamA"
        )
