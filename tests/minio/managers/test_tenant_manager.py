"""Tests for the TenantManager class."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from src.minio.managers.tenant_manager import (
    SYSTEM_GROUPS,
    TenantManager,
    _is_tenant_group,
)
from src.s3.models.tenant import TenantMetadataUpdate, UserProfile
from src.service.exceptions import GroupOperationError
from src.service.kb_auth import AdminPermission, KBaseUser


# ── Fixtures ──────────────────────────────────────────────────────────────


def _make_config():
    cfg = MagicMock()
    cfg.default_bucket = "cdm-lake"
    cfg.tenant_general_warehouse_prefix = "tenant-general-warehouse"
    cfg.tenant_sql_warehouse_prefix = "tenant-sql-warehouse"
    return cfg


def _meta_dict(name="t1", created_by="admin"):
    now = datetime.now(timezone.utc)
    return {
        "tenant_name": name,
        "display_name": name,
        "description": None,
        "website": None,
        "organization": None,
        "created_by": created_by,
        "created_at": now,
        "updated_at": now,
        "updated_by": None,
    }


@pytest.fixture
def mock_metadata_store():
    store = AsyncMock()
    store.list_metadata = AsyncMock(return_value=[])
    store.get_steward_tenants = AsyncMock(return_value=[])
    store.get_metadata = AsyncMock(return_value=_meta_dict())
    store.create_metadata = AsyncMock(return_value=_meta_dict())
    store.update_metadata = AsyncMock(return_value=_meta_dict())
    store.delete_metadata = AsyncMock(return_value=True)
    store.get_stewards = AsyncMock(return_value=[])
    store.is_steward = AsyncMock(return_value=False)
    store.add_steward = AsyncMock(
        return_value={
            "tenant_name": "t1",
            "username": "alice",
            "assigned_by": "admin",
            "assigned_at": datetime.now(timezone.utc),
        }
    )
    store.remove_steward = AsyncMock(return_value=True)
    return store


@pytest.fixture
def mock_group_manager():
    gm = AsyncMock()
    gm.list_resources = AsyncMock(return_value=["t1", "t1ro", "t2", "globalusers"])
    gm.get_group_members = AsyncMock(return_value=["alice", "bob"])
    gm.resource_exists = AsyncMock(return_value=True)
    gm.add_user_to_group = AsyncMock()
    gm.remove_user_from_group = AsyncMock()
    gm.is_user_in_group = AsyncMock(return_value=True)
    return gm


@pytest.fixture
def mock_profile_client():
    pc = AsyncMock()
    pc.get_user_profiles = AsyncMock(
        return_value={
            "alice": UserProfile(
                username="alice", display_name="Alice S", email="alice@org.com"
            ),
            "bob": UserProfile(username="bob", display_name="Bob J", email=None),
        }
    )
    return pc


@pytest.fixture
def manager(mock_metadata_store, mock_group_manager, mock_profile_client):
    return TenantManager(
        metadata_store=mock_metadata_store,
        group_manager=mock_group_manager,
        profile_client=mock_profile_client,
        minio_config=_make_config(),
    )


ADMIN = KBaseUser(user="admin", admin_perm=AdminPermission.FULL)
STEWARD = KBaseUser(user="alice", admin_perm=AdminPermission.NONE)
MEMBER = KBaseUser(user="bob", admin_perm=AdminPermission.NONE)
OUTSIDER = KBaseUser(user="outsider", admin_perm=AdminPermission.NONE)


# ── Helper tests ─────────────────────────────────────────────────────────


class TestIsTenantGroup:
    def test_regular_group(self):
        assert _is_tenant_group("kbase") is True

    def test_ro_group_excluded(self):
        assert _is_tenant_group("kbasero") is False

    def test_globalusers_included(self):
        assert _is_tenant_group("globalusers") is True

    def test_system_groups_empty(self):
        assert len(SYSTEM_GROUPS) == 0


# ── _require_group_exists ────────────────────────────────────────────────


class TestRequireGroupExists:
    @pytest.mark.asyncio
    async def test_rejects_ro_group_name(self, manager):
        with pytest.raises(HTTPException) as exc_info:
            await manager._require_group_exists("kbasero")
        assert exc_info.value.status_code == 400
        assert "read-only group" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_rejects_any_ro_suffix(self, manager):
        with pytest.raises(HTTPException) as exc_info:
            await manager._require_group_exists("mytenantro")
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_allows_base_tenant(self, manager, mock_group_manager):
        mock_group_manager.resource_exists.return_value = True
        await manager._require_group_exists("kbase")  # Should not raise

    @pytest.mark.asyncio
    async def test_nonexistent_group_404(self, manager, mock_group_manager):
        mock_group_manager.resource_exists.return_value = False
        with pytest.raises(HTTPException) as exc_info:
            await manager._require_group_exists("nonexistent")
        assert exc_info.value.status_code == 404


# ── list_tenants ─────────────────────────────────────────────────────────


class TestListTenants:
    @pytest.mark.asyncio
    async def test_returns_summaries(self, manager, mock_metadata_store):
        mock_metadata_store.list_metadata.return_value = [
            _meta_dict("t1"),
            _meta_dict("t2"),
            _meta_dict("globalusers"),
        ]
        result = await manager.list_tenants("alice", "token")
        assert len(result) == 3
        names = [s.tenant_name for s in result]
        assert "t1" in names
        assert "t2" in names
        assert "globalusers" in names

    @pytest.mark.asyncio
    async def test_filters_ro_groups(self, manager, mock_group_manager):
        mock_group_manager.list_resources.return_value = [
            "t1",
            "t1ro",
            "globalusers",
        ]
        result = await manager.list_tenants("alice", "token")
        names = [s.tenant_name for s in result]
        assert "t1" in names
        assert "globalusers" in names
        assert "t1ro" not in names

    @pytest.mark.asyncio
    async def test_is_member_flag(self, manager, mock_group_manager):
        mock_group_manager.list_resources.return_value = ["t1"]
        mock_group_manager.get_group_members.return_value = ["alice"]
        result = await manager.list_tenants("alice", "token")
        assert result[0].is_member is True

    @pytest.mark.asyncio
    async def test_is_steward_flag(
        self, manager, mock_metadata_store, mock_group_manager
    ):
        mock_group_manager.list_resources.return_value = ["t1"]
        mock_metadata_store.get_steward_tenants.return_value = ["t1"]
        result = await manager.list_tenants("alice", "token")
        assert result[0].is_steward is True

    @pytest.mark.asyncio
    async def test_returns_website_in_summary(
        self, manager, mock_metadata_store, mock_group_manager
    ):
        mock_group_manager.list_resources.return_value = ["t1"]
        meta = _meta_dict("t1")
        meta["website"] = "https://example.com"
        mock_metadata_store.list_metadata.return_value = [meta]
        result = await manager.list_tenants("alice", "token")
        assert result[0].tenant_name == "t1"
        assert result[0].website == "https://example.com"

    @pytest.mark.asyncio
    async def test_includes_ro_members_in_count(self, manager, mock_group_manager):
        mock_group_manager.list_resources.return_value = ["t1", "t1ro"]

        async def get_members(name):
            if name == "t1":
                return ["alice"]
            return ["bob"]

        mock_group_manager.get_group_members.side_effect = get_members
        result = await manager.list_tenants("alice", "token")
        assert result[0].member_count == 2


# ── get_tenant_detail ────────────────────────────────────────────────────


class TestGetTenantDetail:
    @pytest.mark.asyncio
    async def test_any_user_can_view(self, manager):
        result = await manager.get_tenant_detail("t1", "token")
        assert result.metadata.tenant_name == "t1"
        assert result.storage_paths is not None

    @pytest.mark.asyncio
    async def test_read_only_no_metadata_write(self, manager, mock_metadata_store):
        """GET detail must not write to DB — returns defaults when metadata missing."""
        mock_metadata_store.get_metadata.return_value = None
        result = await manager.get_tenant_detail("t1", "token")
        assert result.metadata.tenant_name == "t1"
        assert result.metadata.created_by is None
        assert result.metadata.created_at is None
        mock_metadata_store.create_metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_nonexistent_group_404(self, manager, mock_group_manager):
        mock_group_manager.resource_exists.return_value = False
        with pytest.raises(HTTPException) as exc_info:
            await manager.get_tenant_detail("nope", "token")
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_ro_group_error_is_swallowed(self, manager, mock_group_manager):
        """RO group not existing should not break detail view."""
        call_count = 0

        async def get_members(name):
            nonlocal call_count
            call_count += 1
            if name.endswith("ro"):
                raise GroupOperationError("Group not found")
            return ["alice", "bob"]

        mock_group_manager.get_group_members.side_effect = get_members
        result = await manager.get_tenant_detail("t1", "token")
        assert result.member_count == 2


# ── get_tenant_members ───────────────────────────────────────────────────


class TestGetTenantMembers:
    @pytest.mark.asyncio
    async def test_returns_member_list(self, manager):
        result = await manager.get_tenant_members("t1", ADMIN, "token")
        assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_outsider_forbidden(self, manager, mock_group_manager):
        mock_group_manager.get_group_members.return_value = ["alice"]
        with pytest.raises(HTTPException) as exc_info:
            await manager.get_tenant_members("t1", OUTSIDER, "token")
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_steward_can_view(self, manager, mock_metadata_store):
        mock_metadata_store.is_steward.return_value = True
        result = await manager.get_tenant_members("t1", STEWARD, "token")
        assert len(result) >= 1


# ── add_member ───────────────────────────────────────────────────────────


class TestAddMember:
    @pytest.mark.asyncio
    async def test_add_rw_member(self, manager, mock_group_manager):
        result = await manager.add_member("t1", "charlie", "read_write", "token")
        assert result.access_level == "read_write"
        mock_group_manager.add_user_to_group.assert_called_once_with("charlie", "t1")

    @pytest.mark.asyncio
    async def test_add_ro_member(self, manager, mock_group_manager):
        result = await manager.add_member("t1", "charlie", "read_only", "token")
        assert result.access_level == "read_only"
        mock_group_manager.add_user_to_group.assert_called_once_with("charlie", "t1ro")

    @pytest.mark.asyncio
    async def test_nonexistent_group_404(self, manager, mock_group_manager):
        mock_group_manager.resource_exists.return_value = False
        with pytest.raises(HTTPException) as exc_info:
            await manager.add_member("nope", "charlie", "read_write", "token")
        assert exc_info.value.status_code == 404


# ── remove_member ────────────────────────────────────────────────────────


class TestRemoveMember:
    @pytest.mark.asyncio
    async def test_admin_removes_member(self, manager, mock_group_manager):
        await manager.remove_member("t1", "bob", ADMIN)
        assert mock_group_manager.remove_user_from_group.call_count == 2  # RW + RO

    @pytest.mark.asyncio
    async def test_steward_cannot_remove_self(self, manager):
        with pytest.raises(HTTPException) as exc_info:
            await manager.remove_member("t1", "alice", STEWARD)
        assert exc_info.value.status_code == 400
        assert "cannot remove themselves" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_steward_cannot_remove_other_steward(
        self, manager, mock_metadata_store
    ):
        mock_metadata_store.is_steward.return_value = True
        with pytest.raises(HTTPException) as exc_info:
            await manager.remove_member("t1", "bob", STEWARD)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_removes_steward_cascades(self, manager, mock_metadata_store):
        mock_metadata_store.is_steward.return_value = True
        await manager.remove_member("t1", "bob", ADMIN)
        mock_metadata_store.remove_steward.assert_called_once_with("t1", "bob")

    @pytest.mark.asyncio
    async def test_remove_swallows_group_errors(self, manager, mock_group_manager):
        mock_group_manager.remove_user_from_group.side_effect = GroupOperationError(
            "Not in group"
        )
        await manager.remove_member("t1", "bob", ADMIN)  # Should not raise


# ── update_metadata ──────────────────────────────────────────────────────


class TestUpdateMetadata:
    @pytest.mark.asyncio
    async def test_update_success(self, manager, mock_metadata_store):
        update = TenantMetadataUpdate(display_name="New Name")
        result = await manager.update_metadata("t1", update, "steward")
        assert result.tenant_name == "t1"
        mock_metadata_store.update_metadata.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_passes_website_to_store(self, manager, mock_metadata_store):
        meta = _meta_dict()
        meta["website"] = "https://updated.example.com"
        mock_metadata_store.update_metadata.return_value = meta
        update = TenantMetadataUpdate(website="https://updated.example.com")
        result = await manager.update_metadata("t1", update, "steward")
        call_kwargs = mock_metadata_store.update_metadata.call_args.kwargs
        assert call_kwargs["website"] == "https://updated.example.com"
        assert result.website == "https://updated.example.com"

    @pytest.mark.asyncio
    async def test_update_not_found(self, manager, mock_metadata_store):
        mock_metadata_store.update_metadata.return_value = None
        update = TenantMetadataUpdate(display_name="X")
        with pytest.raises(HTTPException) as exc_info:
            await manager.update_metadata("nope", update, "admin")
        assert exc_info.value.status_code == 404


# ── create_metadata ──────────────────────────────────────────────────────


class TestCreateMetadata:
    @pytest.mark.asyncio
    async def test_create_success(self, manager):
        result = await manager.create_metadata("t1", "admin")
        assert result.tenant_name == "t1"

    @pytest.mark.asyncio
    async def test_create_idempotent_returns_existing(
        self, manager, mock_metadata_store
    ):
        """When metadata already exists, create returns the existing record."""
        mock_metadata_store.create_metadata.return_value = None
        existing = _meta_dict("t1", created_by="original_creator")
        mock_metadata_store.get_metadata.return_value = existing
        result = await manager.create_metadata("t1", "admin")
        assert result.tenant_name == "t1"
        assert result.created_by == "original_creator"
        mock_metadata_store.get_metadata.assert_called_once_with("t1")

    @pytest.mark.asyncio
    async def test_create_with_update_body(self, manager, mock_metadata_store):
        update = TenantMetadataUpdate(display_name="Custom", description="Desc")
        await manager.create_metadata("t1", "admin", update)
        call_kwargs = mock_metadata_store.create_metadata.call_args
        assert call_kwargs.kwargs["display_name"] == "Custom"
        assert call_kwargs.kwargs["description"] == "Desc"

    @pytest.mark.asyncio
    async def test_create_passes_website_to_store(self, manager, mock_metadata_store):
        meta = _meta_dict()
        meta["website"] = "https://new.example.com"
        mock_metadata_store.create_metadata.return_value = meta
        update = TenantMetadataUpdate(website="https://new.example.com")
        result = await manager.create_metadata("t1", "admin", update)
        call_kwargs = mock_metadata_store.create_metadata.call_args.kwargs
        assert call_kwargs["website"] == "https://new.example.com"
        assert result.website == "https://new.example.com"

    @pytest.mark.asyncio
    async def test_create_nonexistent_group_404(self, manager, mock_group_manager):
        mock_group_manager.resource_exists.return_value = False
        with pytest.raises(HTTPException) as exc_info:
            await manager.create_metadata("nope", "admin")
        assert exc_info.value.status_code == 404


# ── delete_metadata ──────────────────────────────────────────────────────


class TestDeleteMetadata:
    @pytest.mark.asyncio
    async def test_delete_success(self, manager):
        await manager.delete_metadata("t1")  # Should not raise

    @pytest.mark.asyncio
    async def test_delete_not_found(self, manager, mock_metadata_store):
        mock_metadata_store.delete_metadata.return_value = False
        with pytest.raises(HTTPException) as exc_info:
            await manager.delete_metadata("nope")
        assert exc_info.value.status_code == 404


# ── ensure_metadata ──────────────────────────────────────────────────────


class TestEnsureMetadata:
    @pytest.mark.asyncio
    async def test_returns_existing(self, manager, mock_metadata_store):
        existing = _meta_dict()
        mock_metadata_store.get_metadata.return_value = existing
        result = await manager.ensure_metadata("t1", "system")
        assert result == existing
        mock_metadata_store.create_metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_creates_when_missing(self, manager, mock_metadata_store):
        mock_metadata_store.get_metadata.return_value = None
        result = await manager.ensure_metadata("t1", "system")
        assert result is not None
        mock_metadata_store.create_metadata.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_concurrent_insert(self, manager, mock_metadata_store):
        """If create returns None (concurrent insert won), re-fetch."""
        mock_metadata_store.get_metadata.side_effect = [None, _meta_dict()]
        mock_metadata_store.create_metadata.return_value = None
        result = await manager.ensure_metadata("t1", "system")
        assert result["tenant_name"] == "t1"
        assert mock_metadata_store.get_metadata.call_count == 2


# ── get_stewards ─────────────────────────────────────────────────────────


class TestGetStewards:
    @pytest.mark.asyncio
    async def test_returns_steward_list(self, manager, mock_metadata_store):
        mock_metadata_store.get_stewards.return_value = [
            {
                "username": "alice",
                "assigned_by": "admin",
                "assigned_at": datetime.now(timezone.utc),
            }
        ]
        result = await manager.get_stewards("t1", ADMIN, "token")
        assert len(result) == 1
        assert result[0].username == "alice"

    @pytest.mark.asyncio
    async def test_returns_empty(self, manager):
        result = await manager.get_stewards("t1", ADMIN, "token")
        assert result == []

    @pytest.mark.asyncio
    async def test_outsider_forbidden(self, manager, mock_group_manager):
        mock_group_manager.get_group_members.return_value = ["alice"]
        with pytest.raises(HTTPException) as exc_info:
            await manager.get_stewards("t1", OUTSIDER, "token")
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_nonexistent_group_404(self, manager, mock_group_manager):
        mock_group_manager.resource_exists.return_value = False
        with pytest.raises(HTTPException) as exc_info:
            await manager.get_stewards("nope", ADMIN, "token")
        assert exc_info.value.status_code == 404


# ── add_steward ──────────────────────────────────────────────────────────


class TestAddSteward:
    @pytest.mark.asyncio
    async def test_add_success(self, manager, mock_group_manager):
        mock_group_manager.is_user_in_group.return_value = True
        result = await manager.add_steward("t1", "alice", "admin", "token")
        assert result.username == "alice"

    @pytest.mark.asyncio
    async def test_add_non_member_auto_adds_to_rw(self, manager, mock_group_manager):
        """Non-member is automatically added to the RW group."""
        mock_group_manager.is_user_in_group.return_value = False
        result = await manager.add_steward("t1", "outsider", "admin", "token")
        assert result.username == "outsider"
        mock_group_manager.add_user_to_group.assert_called_once_with("outsider", "t1")

    @pytest.mark.asyncio
    async def test_add_duplicate_is_idempotent(self, manager, mock_metadata_store):
        """Assigning a user who is already a steward returns existing assignment."""
        original_time = datetime.now(timezone.utc)
        mock_metadata_store.add_steward.return_value = {
            "tenant_name": "t1",
            "username": "alice",
            "assigned_by": "original_admin",
            "assigned_at": original_time,
        }
        result = await manager.add_steward("t1", "alice", "admin", "token")
        assert result.username == "alice"
        assert result.assigned_by == "original_admin"


# ── remove_steward ───────────────────────────────────────────────────────


class TestRemoveSteward:
    @pytest.mark.asyncio
    async def test_remove_success(self, manager):
        await manager.remove_steward("t1", "alice")  # Should not raise

    @pytest.mark.asyncio
    async def test_remove_not_found(self, manager, mock_metadata_store):
        mock_metadata_store.remove_steward.return_value = False
        with pytest.raises(HTTPException) as exc_info:
            await manager.remove_steward("t1", "nobody")
        assert exc_info.value.status_code == 404


# ── _build_member_list ───────────────────────────────────────────────────


class TestBuildMemberList:
    def test_rw_precedence_over_ro(self, manager):
        profiles = {
            "alice": UserProfile(username="alice", display_name="Alice", email=None),
        }
        result = manager._build_member_list(
            rw_set={"alice"},
            ro_members=["alice"],
            steward_usernames=set(),
            profiles=profiles,
        )
        assert len(result) == 1
        assert result[0].access_level == "read_write"

    def test_ro_only_member(self, manager):
        profiles = {
            "bob": UserProfile(username="bob"),
        }
        result = manager._build_member_list(
            rw_set=set(),
            ro_members=["bob"],
            steward_usernames=set(),
            profiles=profiles,
        )
        assert len(result) == 1
        assert result[0].access_level == "read_only"

    def test_steward_flag(self, manager):
        profiles = {
            "alice": UserProfile(username="alice"),
        }
        result = manager._build_member_list(
            rw_set={"alice"},
            ro_members=[],
            steward_usernames={"alice"},
            profiles=profiles,
        )
        assert result[0].is_steward is True

    def test_missing_profile_uses_default(self, manager):
        result = manager._build_member_list(
            rw_set={"unknown"},
            ro_members=[],
            steward_usernames=set(),
            profiles={},
        )
        assert result[0].username == "unknown"
        assert result[0].display_name is None


# ── _meta_dict_to_response ───────────────────────────────────────────────


class TestMetaDictToResponse:
    def test_converts_dict(self):
        meta = _meta_dict("t1", "admin")
        result = TenantManager._meta_dict_to_response(meta)
        assert result.tenant_name == "t1"
        assert result.created_by == "admin"

    def test_maps_website(self):
        meta = _meta_dict("t1", "admin")
        meta["website"] = "https://example.com"
        result = TenantManager._meta_dict_to_response(meta)
        assert result.website == "https://example.com"

    def test_maps_website_none(self):
        meta = _meta_dict("t1", "admin")
        result = TenantManager._meta_dict_to_response(meta)
        assert result.website is None
