"""Tests for the tenants router."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.minio.models.tenant import (
    TenantDetailResponse,
    TenantMemberResponse,
    TenantMetadataResponse,
    TenantStewardResponse,
    TenantStoragePaths,
    TenantSummaryResponse,
)
from src.routes.tenants import router
from src.service.dependencies import auth, require_admin
from src.service.exception_handlers import universal_error_handler
from src.service.kb_auth import AdminPermission, KBaseUser


# ── Sample data ───────────────────────────────────────────────────────────

_NOW = datetime(2024, 1, 1)

_META = TenantMetadataResponse(
    tenant_name="t1",
    display_name="Tenant 1",
    description="desc",
    organization="Org",
    created_by="admin",
    created_at=_NOW,
    updated_at=_NOW,
)

_SUMMARY = TenantSummaryResponse(
    tenant_name="t1",
    display_name="Tenant 1",
    description="desc",
    member_count=2,
    is_member=True,
    is_steward=False,
)

_STEWARD = TenantStewardResponse(
    username="alice",
    display_name="Alice",
    email="alice@org.com",
    assigned_by="admin",
    assigned_at=_NOW,
)

_MEMBER = TenantMemberResponse(
    username="bob",
    display_name="Bob",
    email="bob@org.com",
    access_level="read_write",
    is_steward=False,
)

_DETAIL = TenantDetailResponse(
    metadata=_META,
    stewards=[_STEWARD],
    members=[_MEMBER],
    member_count=1,
    storage_paths=TenantStoragePaths(
        general_warehouse="s3a://cdm-lake/tenant-general-warehouse/t1/",
        sql_warehouse="s3a://cdm-lake/tenant-sql-warehouse/t1/",
        namespace_prefix="t1_",
    ),
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def mock_tenant_manager():
    mgr = AsyncMock()
    mgr.list_tenants = AsyncMock(return_value=[_SUMMARY])
    mgr.get_tenant_detail = AsyncMock(return_value=_DETAIL)
    mgr.update_metadata = AsyncMock(return_value=_META)
    mgr.get_tenant_members = AsyncMock(return_value=[_MEMBER])
    mgr.add_member = AsyncMock(return_value=_MEMBER)
    mgr.remove_member = AsyncMock()
    mgr.get_stewards = AsyncMock(return_value=[_STEWARD])
    mgr.add_steward = AsyncMock(return_value=_STEWARD)
    mgr.remove_steward = AsyncMock()
    mgr.create_metadata = AsyncMock(return_value=_META)
    mgr.delete_metadata = AsyncMock()
    # For require_steward_or_admin
    mgr.metadata_store = MagicMock()
    mgr.metadata_store.is_steward = AsyncMock(return_value=True)
    return mgr


@pytest.fixture
def mock_app_state(mock_tenant_manager):
    app_state = MagicMock()
    app_state.tenant_manager = mock_tenant_manager
    return app_state


@pytest.fixture
def admin_user():
    return KBaseUser(user="admin", admin_perm=AdminPermission.FULL)


@pytest.fixture
def regular_user():
    return KBaseUser(user="alice", admin_perm=AdminPermission.NONE)


@pytest.fixture
def admin_app(mock_app_state, admin_user):
    """App where auth returns an admin user."""
    app = FastAPI()
    app.include_router(router)
    app.add_exception_handler(Exception, universal_error_handler)

    app.dependency_overrides[auth] = lambda: admin_user
    app.dependency_overrides[require_admin] = lambda: admin_user

    return app


@pytest.fixture
def admin_client(admin_app, mock_app_state):
    with (
        patch("src.routes.tenants.get_app_state", return_value=mock_app_state),
        patch(
            "src.routes.tenants.require_steward_or_admin",
            new_callable=AsyncMock,
        ),
    ):
        yield TestClient(admin_app, raise_server_exceptions=False)


# ── List tenants ──────────────────────────────────────────────────────────


class TestListTenants:
    def test_list_tenants(self, admin_client, mock_tenant_manager):
        resp = admin_client.get("/tenants", headers={"Authorization": "Bearer tok"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["tenant_name"] == "t1"
        mock_tenant_manager.list_tenants.assert_called_once()


# ── Tenant detail ─────────────────────────────────────────────────────────


class TestGetTenantDetail:
    def test_get_detail(self, admin_client, mock_tenant_manager):
        resp = admin_client.get("/tenants/t1", headers={"Authorization": "Bearer tok"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["metadata"]["tenant_name"] == "t1"
        assert len(data["stewards"]) == 1
        mock_tenant_manager.get_tenant_detail.assert_called_once()


# ── Update metadata ──────────────────────────────────────────────────────


class TestUpdateMetadata:
    def test_patch_metadata(self, admin_client, mock_tenant_manager):
        resp = admin_client.patch(
            "/tenants/t1",
            json={"display_name": "New Name"},
            headers={"Authorization": "Bearer tok"},
        )
        assert resp.status_code == 200
        assert resp.json()["tenant_name"] == "t1"
        mock_tenant_manager.update_metadata.assert_called_once()


# ── Members ───────────────────────────────────────────────────────────────


class TestMembers:
    def test_list_members(self, admin_client, mock_tenant_manager):
        resp = admin_client.get(
            "/tenants/t1/members", headers={"Authorization": "Bearer tok"}
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        mock_tenant_manager.get_tenant_members.assert_called_once()

    def test_add_member(self, admin_client, mock_tenant_manager):
        resp = admin_client.post(
            "/tenants/t1/members/bob", headers={"Authorization": "Bearer tok"}
        )
        assert resp.status_code == 200
        mock_tenant_manager.add_member.assert_called_once()

    def test_add_member_read_only(self, admin_client, mock_tenant_manager):
        resp = admin_client.post(
            "/tenants/t1/members/bob?permission=read_only",
            headers={"Authorization": "Bearer tok"},
        )
        assert resp.status_code == 200
        call_args = mock_tenant_manager.add_member.call_args
        assert call_args[0][2] == "read_only"

    def test_remove_member(self, admin_client, mock_tenant_manager):
        resp = admin_client.delete(
            "/tenants/t1/members/bob", headers={"Authorization": "Bearer tok"}
        )
        assert resp.status_code == 204
        mock_tenant_manager.remove_member.assert_called_once()


# ── Stewards ──────────────────────────────────────────────────────────────


class TestStewards:
    def test_list_stewards(self, admin_client, mock_tenant_manager):
        resp = admin_client.get(
            "/tenants/t1/stewards", headers={"Authorization": "Bearer tok"}
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        mock_tenant_manager.get_stewards.assert_called_once()

    def test_assign_steward(self, admin_client, mock_tenant_manager):
        resp = admin_client.post(
            "/tenants/t1/stewards/alice", headers={"Authorization": "Bearer tok"}
        )
        assert resp.status_code == 200
        mock_tenant_manager.add_steward.assert_called_once()

    def test_remove_steward(self, admin_client, mock_tenant_manager):
        resp = admin_client.delete(
            "/tenants/t1/stewards/alice", headers={"Authorization": "Bearer tok"}
        )
        assert resp.status_code == 204
        mock_tenant_manager.remove_steward.assert_called_once()


# ── Lifecycle (admin only) ────────────────────────────────────────────────


class TestLifecycle:
    def test_create_tenant(self, admin_client, mock_tenant_manager):
        resp = admin_client.post(
            "/tenants/t1",
            headers={"Authorization": "Bearer tok"},
        )
        assert resp.status_code == 200
        mock_tenant_manager.create_metadata.assert_called_once()

    def test_create_tenant_with_body(self, admin_client, mock_tenant_manager):
        resp = admin_client.post(
            "/tenants/t1",
            json={"display_name": "T1", "description": "A tenant"},
            headers={"Authorization": "Bearer tok"},
        )
        assert resp.status_code == 200

    def test_delete_tenant(self, admin_client, mock_tenant_manager):
        resp = admin_client.delete(
            "/tenants/t1",
            headers={"Authorization": "Bearer tok"},
        )
        assert resp.status_code == 204
        mock_tenant_manager.delete_metadata.assert_called_once()
