"""Tests for namespace ACL routes."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from polaris.namespace_acl_manager import (
    NamespaceAclGrantSyncFailure,
    NamespaceAclGrantOperationResult,
    NamespaceAclNamespaceNotFoundError,
    NamespaceAclUserSyncResult,
    NamespaceAclValidationError,
)
from polaris.namespace_acl_store import NamespaceAclGrantRecord
from routes.namespace_acls import router
from service import app_state
from service.dependencies import auth
from service.exception_handlers import universal_error_handler
from service.kb_auth import AdminPermission, KBaseUser


NOW = datetime(2026, 4, 26, tzinfo=UTC)


@pytest.fixture
def steward_user():
    """Create a steward user."""
    return KBaseUser(user="steward", admin_perm=AdminPermission.NONE)


@pytest.fixture
def admin_user():
    """Create an admin user."""
    return KBaseUser(user="admin", admin_perm=AdminPermission.FULL)


@pytest.fixture
def grant_record():
    """Create a namespace ACL grant record."""
    return NamespaceAclGrantRecord(
        id="grant-id",
        role_id="role-id",
        tenant_name="kbase",
        catalog_name="tenant_kbase",
        namespace_name="shared_data",
        namespace_parts=("shared_data",),
        username="alice",
        access_level="read",
        status="active",
        granted_by="steward",
        granted_at=NOW,
        updated_by="system",
        updated_at=NOW,
        revoked_by=None,
        revoked_at=None,
        last_synced_at=NOW,
        last_sync_error=None,
    )


@pytest.fixture
def mock_state(grant_record):
    """Create mocked application state."""
    state = MagicMock()
    state.tenant_manager = MagicMock()
    state.tenant_manager.metadata_store = MagicMock()
    state.tenant_manager.metadata_store.is_steward = AsyncMock(return_value=True)

    state.group_manager = MagicMock()
    state.group_manager.resource_exists = AsyncMock(return_value=True)
    state.group_manager.get_group_members = AsyncMock(return_value=[])

    state.user_manager = MagicMock()
    state.user_manager.resource_exists = AsyncMock(return_value=True)
    state.user_manager.create_user = AsyncMock(return_value=None)

    state.polaris_service = MagicMock()
    state.polaris_service.namespace_exists = AsyncMock(return_value=True)

    profile = MagicMock()
    profile.display_name = "Alice"
    profile.email = "alice@example.com"
    state.profile_client = MagicMock()
    state.profile_client.get_user_profiles = AsyncMock(return_value={"alice": profile})

    sync_result = NamespaceAclUserSyncResult(
        username="alice",
        policy_name="namespace-acl-alice",
        synced_grants=("grant-id",),
        failed_grants=(),
        revoked_stale_roles=(),
        policy_size_bytes=512,
    )
    state.namespace_acl_manager = MagicMock()
    state.namespace_acl_manager.validate_namespace_for_grant = AsyncMock(
        return_value=None
    )
    state.namespace_acl_manager.is_shadowed_by_tenant_membership = AsyncMock(
        return_value=False
    )
    state.namespace_acl_manager.grant_namespace_access = AsyncMock(
        return_value=NamespaceAclGrantOperationResult(
            grant=grant_record,
            created=True,
            sync_result=sync_result,
        )
    )
    state.namespace_acl_manager.revoke_namespace_access = AsyncMock(
        return_value=NamespaceAclGrantOperationResult(
            grant=grant_record.model_copy()
            if hasattr(grant_record, "model_copy")
            else grant_record,
            created=False,
            sync_result=sync_result,
        )
    )
    state.namespace_acl_manager.list_grants_for_tenant = AsyncMock(
        return_value=[grant_record]
    )
    state.namespace_acl_manager.list_grants_for_user = AsyncMock(
        return_value=[grant_record]
    )
    state.namespace_acl_manager.reconcile_user = AsyncMock(return_value=sync_result)
    state.namespace_acl_manager.list_usernames_for_sync = AsyncMock(
        return_value=["alice"]
    )
    return state


def _create_test_app(mock_state, authenticated_user):
    """Create a test FastAPI app."""
    test_app = FastAPI()
    test_app.state._minio_manager_state = mock_state
    test_app.include_router(router)
    test_app.add_exception_handler(Exception, universal_error_handler)
    test_app.dependency_overrides[auth] = lambda: authenticated_user
    test_app.dependency_overrides[app_state.get_app_state] = lambda: mock_state
    return test_app


def test_grant_namespace_acl(mock_state, steward_user):
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    assert response.status_code == 201
    assert response.json()["id"] == "grant-id"
    mock_state.user_manager.create_user.assert_not_called()
    mock_state.namespace_acl_manager.grant_namespace_access.assert_called_once_with(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        access_level="read",
        actor="steward",
        shadowed=False,
    )


def test_grant_namespace_acl_returns_200_for_idempotent_grant(
    mock_state,
    steward_user,
    grant_record,
):
    sync_result = NamespaceAclUserSyncResult(
        username="alice",
        policy_name="namespace-acl-alice",
        synced_grants=("grant-id",),
        failed_grants=(),
        revoked_stale_roles=(),
        policy_size_bytes=512,
    )
    mock_state.namespace_acl_manager.grant_namespace_access.return_value = (
        NamespaceAclGrantOperationResult(
            grant=grant_record,
            created=False,
            sync_result=sync_result,
        )
    )
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    assert response.status_code == 200
    assert response.json()["id"] == "grant-id"


def test_grant_namespace_acl_returns_500_when_grant_cannot_be_loaded(
    mock_state,
    steward_user,
):
    sync_result = NamespaceAclUserSyncResult(
        username="alice",
        policy_name="namespace-acl-alice",
        synced_grants=("grant-id",),
        failed_grants=(),
        revoked_stale_roles=(),
        policy_size_bytes=512,
    )
    mock_state.namespace_acl_manager.grant_namespace_access.return_value = (
        NamespaceAclGrantOperationResult(
            grant=None,
            created=True,
            sync_result=sync_result,
        )
    )
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Grant was recorded but could not be loaded"


def test_grant_namespace_acl_returns_207_when_sync_fails(
    mock_state,
    steward_user,
    grant_record,
):
    sync_result = NamespaceAclUserSyncResult(
        username="alice",
        policy_name="namespace-acl-alice",
        synced_grants=(),
        failed_grants=(
            NamespaceAclGrantSyncFailure(
                grant_id="grant-id",
                username="alice",
                message="policy too large",
            ),
        ),
        revoked_stale_roles=(),
        policy_size_bytes=25000,
    )
    mock_state.namespace_acl_manager.grant_namespace_access.return_value = (
        NamespaceAclGrantOperationResult(
            grant=grant_record,
            created=True,
            sync_result=sync_result,
        )
    )
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    # 207 Multi-Status: grant intent is recorded; partial-sync failures are
    # surfaced via the grant payload (status, last_sync_error) rather than via
    # an HTTP error code.
    assert response.status_code == 207
    body = response.json()
    assert body["id"] == "grant-id"
    assert body["status"] == "active"


def test_grant_namespace_acl_provisions_missing_minio_user(mock_state, steward_user):
    mock_state.user_manager.resource_exists.return_value = False
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    assert response.status_code == 201
    mock_state.user_manager.create_user.assert_called_once_with("alice")


def test_grant_namespace_acl_marks_shadowed_for_rw_member(mock_state, steward_user):
    mock_state.namespace_acl_manager.is_shadowed_by_tenant_membership.return_value = (
        True
    )
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "write",
        },
    )

    assert response.status_code == 201
    assert (
        mock_state.namespace_acl_manager.grant_namespace_access.call_args.kwargs[
            "shadowed"
        ]
        is True
    )


def test_grant_namespace_acl_returns_404_when_kbase_user_unknown(
    mock_state,
    steward_user,
):
    """The grant route must reject typo'd usernames before MinIO/Polaris fan-out."""
    mock_state.profile_client.get_user_profiles.return_value = {}
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "bogus_user",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    assert response.status_code == 404
    assert "bogus_user" in response.json()["detail"]
    # No fan-out: namespace validation must precede user provisioning, but the
    # KBase profile lookup must precede _ensure_minio_user.
    mock_state.user_manager.create_user.assert_not_called()
    mock_state.namespace_acl_manager.grant_namespace_access.assert_not_called()


def test_grant_namespace_acl_validates_namespace_before_user_provisioning(
    mock_state,
    steward_user,
):
    """A typo'd namespace must short-circuit the route before creating a MinIO user."""
    mock_state.user_manager.resource_exists.return_value = False
    mock_state.namespace_acl_manager.validate_namespace_for_grant.side_effect = (
        NamespaceAclNamespaceNotFoundError("Namespace not found")
    )

    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["typo_namespace"],
            "access_level": "read",
        },
    )

    assert response.status_code == 404
    mock_state.user_manager.create_user.assert_not_called()
    mock_state.profile_client.get_user_profiles.assert_not_called()
    mock_state.namespace_acl_manager.grant_namespace_access.assert_not_called()


def test_grant_namespace_acl_returns_404_for_missing_namespace_in_manager(
    mock_state,
    steward_user,
):
    """Validation may also fail inside the manager (race conditions)."""
    mock_state.namespace_acl_manager.grant_namespace_access.side_effect = (
        NamespaceAclNamespaceNotFoundError("namespace not found")
    )
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "namespace not found"


def test_grant_namespace_acl_returns_409_for_invalid_namespace(
    mock_state,
    steward_user,
):
    mock_state.namespace_acl_manager.grant_namespace_access.side_effect = (
        NamespaceAclValidationError("child namespaces exist")
    )
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.post(
        "/tenants/kbase/namespace-acls",
        json={
            "username": "alice",
            "namespace": ["shared_data"],
            "access_level": "read",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "child namespaces exist"


def test_list_namespace_acls_rejects_read_only_group_name(mock_state, steward_user):
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.get("/tenants/kbasero/namespace-acls")

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Use the base tenant name, not the read-only group name"
    )


def test_list_namespace_acls_returns_404_for_missing_tenant(mock_state, steward_user):
    mock_state.group_manager.resource_exists.return_value = False
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.get("/tenants/kbase/namespace-acls")

    assert response.status_code == 404
    assert response.json()["detail"] == "Tenant 'kbase' not found"


def test_list_namespace_acls(mock_state, steward_user):
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.get("/tenants/kbase/namespace-acls?namespace=shared_data")

    assert response.status_code == 200
    assert response.json()[0]["namespace"] == ["shared_data"]
    mock_state.namespace_acl_manager.list_grants_for_tenant.assert_called_once_with(
        "kbase",
        ["shared_data"],
    )


def test_revoke_namespace_acl(mock_state, steward_user):
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.request(
        "DELETE",
        "/tenants/kbase/namespace-acls",
        json={"username": "alice", "namespace": ["shared_data"]},
    )

    assert response.status_code == 200
    assert response.json()["id"] == "grant-id"
    mock_state.namespace_acl_manager.revoke_namespace_access.assert_called_once_with(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        actor="steward",
    )


def test_revoke_namespace_acl_returns_404_for_missing_grant(mock_state, steward_user):
    mock_state.namespace_acl_manager.revoke_namespace_access.return_value = None
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.request(
        "DELETE",
        "/tenants/kbase/namespace-acls",
        json={"username": "alice", "namespace": ["shared_data"]},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "No active namespace ACL grant found"


def test_revoke_namespace_acl_returns_207_when_sync_fails(
    mock_state,
    steward_user,
    grant_record,
):
    sync_result = NamespaceAclUserSyncResult(
        username="alice",
        policy_name="namespace-acl-alice",
        synced_grants=(),
        failed_grants=(
            NamespaceAclGrantSyncFailure(
                grant_id="grant-id",
                username="alice",
                message="failed to detach policy",
            ),
        ),
        revoked_stale_roles=(),
        policy_size_bytes=0,
    )
    mock_state.namespace_acl_manager.revoke_namespace_access.return_value = (
        NamespaceAclGrantOperationResult(
            grant=grant_record,
            created=False,
            sync_result=sync_result,
        )
    )
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.request(
        "DELETE",
        "/tenants/kbase/namespace-acls",
        json={"username": "alice", "namespace": ["shared_data"]},
    )

    # 207 Multi-Status: revocation is recorded in MMS; cleanup of Polaris/MinIO
    # is partially failed and surfaced via the grant payload.
    assert response.status_code == 207
    assert response.json()["id"] == "grant-id"


def test_list_my_namespace_acls(mock_state, steward_user):
    app = _create_test_app(mock_state, steward_user)
    client = TestClient(app)

    response = client.get("/me/namespace-acls")

    assert response.status_code == 200
    assert response.json()[0]["username"] == "alice"
    mock_state.namespace_acl_manager.list_grants_for_user.assert_called_once_with(
        "steward"
    )


def test_sync_namespace_acls_admin(mock_state, admin_user):
    app = _create_test_app(mock_state, admin_user)
    client = TestClient(app)

    response = client.post("/management/migrate/sync-namespace-acls?username=alice")

    assert response.status_code == 200
    assert response.json()["policy_name"] == "namespace-acl-alice"
    mock_state.namespace_acl_manager.reconcile_user.assert_called_once_with("alice")


def test_sync_namespace_acls_for_tenant(mock_state, admin_user):
    app = _create_test_app(mock_state, admin_user)
    client = TestClient(app)

    response = client.post("/management/migrate/sync-namespace-acls?tenant=kbase")

    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "tenant"
    assert body["tenant_name"] == "kbase"
    assert body["reconciled_users"] == ["alice"]
    mock_state.namespace_acl_manager.list_usernames_for_sync.assert_called_once_with(
        tenant_name="kbase"
    )
    mock_state.namespace_acl_manager.reconcile_user.assert_called_once_with("alice")


def test_sync_namespace_acls_rejects_username_and_tenant(mock_state, admin_user):
    app = _create_test_app(mock_state, admin_user)
    client = TestClient(app)

    response = client.post(
        "/management/migrate/sync-namespace-acls?username=alice&tenant=kbase"
    )

    assert response.status_code == 400
