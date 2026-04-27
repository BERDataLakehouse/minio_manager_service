"""Tests for namespace ACL reconciliation manager."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from polaris.namespace_acl_manager import NamespaceAclManager
from polaris.namespace_acl_manager import (
    NamespaceAclNamespaceNotFoundError,
    NamespaceAclValidationError,
)
from polaris.namespace_acl_policy import namespace_acl_policy_name
from polaris.namespace_acl_store import (
    EVENT_GRANT_ACTIVATED,
    EVENT_GRANT_SHADOWED,
    EVENT_SYNC_FAILED,
    EVENT_VALIDATION_FAILED,
    GRANT_STATUS_ACTIVE,
    GRANT_STATUS_PENDING,
    GRANT_STATUS_SHADOWED,
    GRANT_STATUS_SYNC_ERROR,
    NamespaceAclGrantRecord,
    NamespaceAclGrantMutation,
    NamespaceAclRoleRecord,
)
from s3.models.s3_config import S3Config


NOW = datetime(2026, 4, 26, tzinfo=UTC)


class MockLockManager:
    """Lock manager test double."""

    @asynccontextmanager
    async def namespace_acl_lock(self, username):
        yield


@pytest.fixture
def s3_config():
    """Create S3Config for manager tests."""
    return S3Config(
        endpoint="http://minio:9002",
        access_key="minio",
        secret_key="minio123",
        secure=False,
    )


@pytest.fixture
def store():
    """Create a mocked namespace ACL store."""
    mock_store = MagicMock()
    mock_store.list_active_grants_for_user = AsyncMock(return_value=[])
    mock_store.get_role = AsyncMock(return_value=None)
    mock_store.list_grants_for_tenant = AsyncMock(return_value=[])
    mock_store.list_roles_for_tenant = AsyncMock(return_value=[])
    mock_store.revoke_grant = AsyncMock(return_value=None)
    mock_store.update_grant_status = AsyncMock(return_value=None)
    mock_store.append_event = AsyncMock(return_value=None)
    mock_store.count_active_grants_for_role = AsyncMock(return_value=0)
    mock_store.delete_role = AsyncMock(return_value=False)
    mock_store.delete_roles_for_tenant = AsyncMock(return_value=0)
    return mock_store


@pytest.fixture
def polaris_service():
    """Create a mocked Polaris service."""
    service = MagicMock()
    service.create_principal = AsyncMock(return_value={})
    service.namespace_exists = AsyncMock(return_value=True)
    service.list_namespaces = AsyncMock(return_value=[])
    service.list_tables_in_namespace = AsyncMock(return_value=[])
    service.load_table = AsyncMock(return_value={})
    service.ensure_namespace_acl_role_bindings = AsyncMock(return_value=None)
    service.grant_principal_role_to_principal = AsyncMock(return_value=None)
    service.get_principal_roles_for_principal = AsyncMock(return_value=[])
    service.revoke_principal_role_from_principal = AsyncMock(return_value=None)
    service.delete_principal_role = AsyncMock(return_value=None)
    service.delete_catalog_role = AsyncMock(return_value=None)
    return service


@pytest.fixture
def policy_manager():
    """Create a mocked policy manager."""
    manager = MagicMock()
    manager.upsert_attached_user_policy = AsyncMock(return_value=None)
    manager.detach_and_delete_user_policy = AsyncMock(return_value=None)
    return manager


@pytest.fixture
def manager(store, polaris_service, policy_manager, s3_config):
    """Create NamespaceAclManager with mocked dependencies."""
    return NamespaceAclManager(
        store=store,
        polaris_service=polaris_service,
        policy_manager=policy_manager,
        lock_manager=MockLockManager(),
        minio_config=s3_config,
    )


def _grant(
    grant_id="grant-id",
    role_id="role-id",
    access_level="read",
    status="pending",
):
    return NamespaceAclGrantRecord(
        id=grant_id,
        role_id=role_id,
        tenant_name="kbase",
        catalog_name="tenant_kbase",
        namespace_name="shared_data",
        namespace_parts=("shared_data",),
        username="alice",
        access_level=access_level,
        status=status,
        granted_by="steward",
        granted_at=NOW,
        updated_by="steward",
        updated_at=NOW,
        revoked_by=None,
        revoked_at=None,
        last_synced_at=None,
        last_sync_error=None,
    )


def _role(access_level="read"):
    return NamespaceAclRoleRecord(
        id="role-id",
        tenant_name="kbase",
        catalog_name="tenant_kbase",
        namespace_name="shared_data",
        namespace_parts=("shared_data",),
        access_level=access_level,
        catalog_role_name=f"namespace_acl_hash_{access_level}",
        principal_role_name=f"namespace_acl_hash_{access_level}_member",
        role_name_hash_len=24,
        created_at=NOW,
        updated_at=NOW,
    )


@pytest.mark.asyncio
async def test_reconcile_user_with_no_grants_removes_policy_and_stale_roles(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    polaris_service.get_principal_roles_for_principal.return_value = [
        "namespace_acl_old_read_member",
        "kbase_member",
    ]

    result = await manager.reconcile_user("alice")

    assert result.success is True
    assert result.policy_name == namespace_acl_policy_name("alice")
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    polaris_service.revoke_principal_role_from_principal.assert_called_once_with(
        "alice",
        "namespace_acl_old_read_member",
    )
    store.update_grant_status.assert_not_called()


@pytest.mark.asyncio
async def test_reconcile_user_syncs_grant(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role

    result = await manager.reconcile_user("alice")

    assert result.success is True
    assert result.synced_grants == ("grant-id",)
    assert result.failed_grants == ()
    polaris_service.create_principal.assert_called_once_with("alice")
    polaris_service.ensure_namespace_acl_role_bindings.assert_called_once_with(
        catalog="tenant_kbase",
        catalog_role="namespace_acl_hash_read",
        principal_role="namespace_acl_hash_read_member",
        namespace=("shared_data",),
        access_level="read",
    )
    polaris_service.grant_principal_role_to_principal.assert_called_once_with(
        "alice",
        "namespace_acl_hash_read_member",
    )
    policy_manager.upsert_attached_user_policy.assert_called_once()
    policy_arg = policy_manager.upsert_attached_user_policy.call_args.args[0]
    assert policy_arg.policy_name == "namespace-acl-alice"
    assert result.policy_size_bytes > 0
    store.update_grant_status.assert_called_once()
    assert store.update_grant_status.call_args.kwargs["status"] == "active"


@pytest.mark.asyncio
async def test_reconcile_user_marks_missing_role_sync_error(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    grant = _grant()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = None

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.failed_grants[0].grant_id == "grant-id"
    polaris_service.ensure_namespace_acl_role_bindings.assert_not_called()
    policy_manager.upsert_attached_user_policy.assert_not_called()
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    store.update_grant_status.assert_called_once_with(
        grant_id="grant-id",
        status=GRANT_STATUS_SYNC_ERROR,
        actor="system",
        last_synced_at=None,
        last_sync_error="namespace ACL role metadata is missing",
        event_type=EVENT_SYNC_FAILED,
        message="namespace ACL role metadata is missing",
    )


@pytest.mark.asyncio
async def test_reconcile_user_marks_all_failed_when_principal_create_fails(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    grant = _grant()
    store.list_active_grants_for_user.return_value = [grant]
    polaris_service.create_principal.side_effect = Exception("principal failed")

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.failed_grants[0].message == (
        "failed to provision Polaris principal: principal failed"
    )
    store.get_role.assert_not_called()
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    store.update_grant_status.assert_called_once()
    assert store.update_grant_status.call_args.kwargs["status"] == (
        GRANT_STATUS_SYNC_ERROR
    )
    assert store.update_grant_status.call_args.kwargs["event_type"] == (
        EVENT_SYNC_FAILED
    )


@pytest.mark.asyncio
async def test_reconcile_user_enforces_grant_count_cap(
    store,
    polaris_service,
    policy_manager,
    s3_config,
):
    grants = [_grant(grant_id="grant-1"), _grant(grant_id="grant-2")]
    store.list_active_grants_for_user.return_value = grants
    manager = NamespaceAclManager(
        store=store,
        polaris_service=polaris_service,
        policy_manager=policy_manager,
        lock_manager=MockLockManager(),
        minio_config=s3_config,
        max_grants_per_user=1,
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert len(result.failed_grants) == 2
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    assert store.update_grant_status.call_count == 2
    assert "exceeds configured limit" in result.failed_grants[0].message


@pytest.mark.asyncio
async def test_reconcile_user_reports_cleanup_failure_for_grant_count_cap(
    store,
    polaris_service,
    policy_manager,
    s3_config,
):
    grant = _grant()
    store.list_active_grants_for_user.return_value = [grant]
    policy_manager.detach_and_delete_user_policy.side_effect = Exception(
        "cleanup failed"
    )
    manager = NamespaceAclManager(
        store=store,
        polaris_service=polaris_service,
        policy_manager=policy_manager,
        lock_manager=MockLockManager(),
        minio_config=s3_config,
        max_grants_per_user=0,
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert len(result.failed_grants) == 2
    assert result.failed_grants[-1].grant_id == ""
    assert "cleanup failed" in result.failed_grants[-1].message


@pytest.mark.asyncio
async def test_reconcile_user_marks_grant_failed_when_polaris_assignment_fails(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role
    polaris_service.ensure_namespace_acl_role_bindings.side_effect = Exception(
        "polaris failed"
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.synced_grants == ()
    assert result.failed_grants[0].message == "polaris failed"
    policy_manager.upsert_attached_user_policy.assert_not_called()
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    store.update_grant_status.assert_called_once_with(
        grant_id="grant-id",
        status=GRANT_STATUS_SYNC_ERROR,
        actor="system",
        last_synced_at=None,
        last_sync_error="polaris failed",
        event_type=EVENT_SYNC_FAILED,
        message="polaris failed",
    )


@pytest.mark.asyncio
async def test_reconcile_user_enforces_policy_size_cap(
    store,
    polaris_service,
    policy_manager,
    s3_config,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role
    manager = NamespaceAclManager(
        store=store,
        polaris_service=polaris_service,
        policy_manager=policy_manager,
        lock_manager=MockLockManager(),
        minio_config=s3_config,
        max_policy_bytes=1,
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.synced_grants == ()
    assert "exceeding configured limit of 1" in result.failed_grants[0].message
    policy_manager.upsert_attached_user_policy.assert_not_called()
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    store.update_grant_status.assert_called_once()
    assert store.update_grant_status.call_args.kwargs["status"] == (
        GRANT_STATUS_SYNC_ERROR
    )


@pytest.mark.asyncio
async def test_reconcile_user_reports_cleanup_failure_for_oversized_policy(
    store,
    polaris_service,
    policy_manager,
    s3_config,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role
    policy_manager.detach_and_delete_user_policy.side_effect = Exception(
        "cleanup failed"
    )
    manager = NamespaceAclManager(
        store=store,
        polaris_service=polaris_service,
        policy_manager=policy_manager,
        lock_manager=MockLockManager(),
        minio_config=s3_config,
        max_policy_bytes=1,
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert len(result.failed_grants) == 2
    assert result.failed_grants[-1].grant_id == ""
    assert "oversized namespace ACL policy" in result.failed_grants[-1].message


@pytest.mark.asyncio
async def test_reconcile_user_marks_grant_failed_when_minio_policy_sync_fails(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role
    policy_manager.upsert_attached_user_policy.side_effect = Exception("minio failed")

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.synced_grants == ()
    assert result.failed_grants[0].grant_id == "grant-id"
    assert "failed to sync MinIO namespace ACL policy: minio failed" == (
        result.failed_grants[0].message
    )
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    store.update_grant_status.assert_called_once_with(
        grant_id="grant-id",
        status=GRANT_STATUS_SYNC_ERROR,
        actor="system",
        last_synced_at=None,
        last_sync_error="failed to sync MinIO namespace ACL policy: minio failed",
        event_type=EVENT_SYNC_FAILED,
        message="failed to sync MinIO namespace ACL policy: minio failed",
    )
    polaris_service.revoke_principal_role_from_principal.assert_not_called()


@pytest.mark.asyncio
async def test_reconcile_user_reports_cleanup_failure_after_minio_sync_failure(
    manager,
    store,
    policy_manager,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role
    policy_manager.upsert_attached_user_policy.side_effect = Exception("minio failed")
    policy_manager.detach_and_delete_user_policy.side_effect = Exception(
        "cleanup failed"
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert len(result.failed_grants) == 2
    assert result.failed_grants[-1].grant_id == ""
    assert "after sync failure: cleanup failed" in result.failed_grants[-1].message


@pytest.mark.asyncio
async def test_reconcile_user_reports_cleanup_failure_for_empty_policy(
    manager,
    store,
    policy_manager,
):
    store.list_active_grants_for_user.return_value = []
    policy_manager.detach_and_delete_user_policy.side_effect = Exception(
        "cleanup failed"
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.failed_grants[0].grant_id == ""
    assert "empty namespace ACL policy" in result.failed_grants[0].message


@pytest.mark.asyncio
async def test_reconcile_user_marks_candidates_failed_when_stale_role_revoke_fails(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role
    polaris_service.get_principal_roles_for_principal.side_effect = Exception(
        "stale cleanup failed"
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert any(
        "failed to revoke stale Polaris namespace ACL roles" in failure.message
        for failure in result.failed_grants
    )
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )
    assert store.update_grant_status.call_count >= 2


@pytest.mark.asyncio
async def test_reconcile_user_reports_cleanup_failure_after_stale_role_failure(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    grant = _grant()
    role = _role()
    store.list_active_grants_for_user.return_value = [grant]
    store.get_role.return_value = role
    polaris_service.get_principal_roles_for_principal.side_effect = Exception(
        "stale cleanup failed"
    )
    policy_manager.detach_and_delete_user_policy.side_effect = Exception(
        "policy cleanup failed"
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.failed_grants[-1].grant_id == ""
    assert "after stale role cleanup failure" in result.failed_grants[-1].message


@pytest.mark.asyncio
async def test_reconcile_user_reports_stale_role_failure_without_candidates(
    manager,
    store,
    polaris_service,
    policy_manager,
):
    store.list_active_grants_for_user.return_value = []
    polaris_service.get_principal_roles_for_principal.side_effect = Exception(
        "stale cleanup failed"
    )

    result = await manager.reconcile_user("alice")

    assert result.success is False
    assert result.failed_grants[0].grant_id == ""
    assert "failed to revoke stale Polaris namespace ACL roles" in (
        result.failed_grants[0].message
    )
    assert policy_manager.detach_and_delete_user_policy.call_count == 2
    policy_manager.detach_and_delete_user_policy.assert_any_call(
        "namespace-acl-alice",
        "alice",
    )


@pytest.mark.asyncio
async def test_validate_namespace_accepts_leaf_with_tables(manager, polaris_service):
    polaris_service.list_tables_in_namespace.return_value = ["measurements"]
    polaris_service.load_table.return_value = {
        "metadata": {
            "location": "s3a://cdm-lake/tenant-sql-warehouse/kbase/iceberg/shared_data/measurements"
        }
    }

    await manager.validate_namespace_for_grant("kbase", ["shared_data"])

    polaris_service.namespace_exists.assert_called_once_with(
        "tenant_kbase",
        ("shared_data",),
    )
    polaris_service.list_namespaces.assert_called_once_with(
        "tenant_kbase",
        parent=("shared_data",),
    )
    polaris_service.load_table.assert_called_once_with(
        "tenant_kbase",
        ("shared_data",),
        "measurements",
    )


@pytest.mark.asyncio
async def test_validate_namespace_accepts_top_level_table_location(
    manager,
    polaris_service,
):
    polaris_service.list_tables_in_namespace.return_value = ["measurements"]
    polaris_service.load_table.return_value = {
        "metadata-location": (
            "s3a://cdm-lake/tenant-sql-warehouse/kbase/iceberg/"
            "shared_data/measurements/metadata.json"
        )
    }

    await manager.validate_namespace_for_grant("kbase", ["shared_data"])


@pytest.mark.asyncio
async def test_validate_namespace_rejects_missing_namespace(
    manager,
    polaris_service,
):
    polaris_service.namespace_exists.return_value = False

    with pytest.raises(NamespaceAclNamespaceNotFoundError):
        await manager.validate_namespace_for_grant("kbase", ["shared_data"])


@pytest.mark.asyncio
async def test_validate_namespace_rejects_child_namespaces(
    manager,
    polaris_service,
):
    polaris_service.list_namespaces.return_value = [("shared_data", "child")]

    with pytest.raises(NamespaceAclValidationError, match="child namespaces"):
        await manager.validate_namespace_for_grant("kbase", ["shared_data"])


@pytest.mark.asyncio
async def test_validate_namespace_rejects_external_table_location(
    manager,
    polaris_service,
):
    polaris_service.list_tables_in_namespace.return_value = ["measurements"]
    polaris_service.load_table.return_value = {
        "metadata": {
            "location": "s3a://cdm-lake/tenant-sql-warehouse/other/iceberg/shared_data/measurements"
        }
    }

    with pytest.raises(NamespaceAclValidationError, match="outside"):
        await manager.validate_namespace_for_grant("kbase", ["shared_data"])


@pytest.mark.asyncio
async def test_validate_namespace_rejects_table_without_location(
    manager,
    polaris_service,
):
    polaris_service.list_tables_in_namespace.return_value = ["measurements"]
    polaris_service.load_table.return_value = {}

    with pytest.raises(NamespaceAclValidationError, match="does not expose"):
        await manager.validate_namespace_for_grant("kbase", ["shared_data"])


@pytest.mark.asyncio
async def test_grant_namespace_access_validates_and_provisions_principal(
    manager,
    store,
    polaris_service,
):
    grant = _grant(status="pending")
    store.create_or_update_grant = AsyncMock(
        return_value=NamespaceAclGrantMutation(
            grant=grant,
            created=True,
            event_type="grant_created",
        )
    )
    store.get_active_grant = AsyncMock(return_value=grant)

    result = await manager.grant_namespace_access(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        access_level="read",
        actor="steward",
    )

    assert result.created is True
    polaris_service.create_principal.assert_called_once_with("alice")
    store.create_or_update_grant.assert_called_once()


@pytest.mark.asyncio
async def test_grant_namespace_access_records_validation_failure(
    manager,
    store,
    polaris_service,
):
    polaris_service.namespace_exists.return_value = False

    with pytest.raises(NamespaceAclNamespaceNotFoundError):
        await manager.grant_namespace_access(
            tenant_name="kbase",
            namespace_parts=["shared_data"],
            username="alice",
            access_level="read",
            actor="steward",
        )

    store.append_event.assert_called_once_with(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        event_type=EVENT_VALIDATION_FAILED,
        actor="steward",
        message="Namespace 'shared_data' not found in tenant 'kbase'",
    )
    polaris_service.create_principal.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_namespace_access_returns_none_when_no_active_grant(
    manager,
    store,
):
    store.revoke_grant.return_value = None

    result = await manager.revoke_namespace_access(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        actor="steward",
    )

    assert result is None


@pytest.mark.asyncio
async def test_revoke_namespace_access_reconciles_user_after_revoke(
    manager,
    store,
    policy_manager,
):
    grant = _grant(status="active")
    store.revoke_grant.return_value = grant
    store.list_active_grants_for_user.return_value = []

    result = await manager.revoke_namespace_access(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        actor="steward",
    )

    assert result is not None
    assert result.grant == grant
    assert result.created is False
    assert result.sync_result.success is True
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )


@pytest.mark.asyncio
async def test_list_grants_delegate_to_store(manager, store):
    grants = [_grant()]
    store.list_grants_for_tenant.return_value = grants
    store.list_active_grants_for_user.return_value = grants

    assert await manager.list_grants_for_tenant("kbase", ["shared_data"]) == grants
    assert await manager.list_grants_for_user("alice") == grants
    store.list_grants_for_tenant.assert_called_once_with("kbase", ["shared_data"])
    store.list_active_grants_for_user.assert_called_once_with(
        "alice",
        statuses=(
            GRANT_STATUS_PENDING,
            GRANT_STATUS_ACTIVE,
            GRANT_STATUS_SHADOWED,
            GRANT_STATUS_SYNC_ERROR,
        ),
    )


@pytest.mark.asyncio
async def test_list_usernames_for_sync_delegates_to_store(manager, store):
    store.list_usernames_for_sync = AsyncMock(return_value=["alice", "bob"])

    result = await manager.list_usernames_for_sync(tenant_name="kbase")

    assert result == ["alice", "bob"]
    store.list_usernames_for_sync.assert_called_once_with(tenant_name="kbase")


@pytest.mark.asyncio
async def test_record_validation_failure_appends_audit_event(manager, store):
    await manager.record_validation_failure(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        actor="steward",
        message="invalid namespace",
    )

    store.append_event.assert_called_once_with(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        event_type=EVENT_VALIDATION_FAILED,
        actor="steward",
        message="invalid namespace",
    )


@pytest.mark.asyncio
async def test_reconcile_tenant_membership_shadows_rw_member_grants(
    manager,
    store,
):
    grant = _grant(status="active")
    store.list_active_grants_for_user.side_effect = [[grant], []]

    await manager.reconcile_tenant_membership("alice", "kbase", "read_write")

    store.update_grant_status.assert_called_once_with(
        grant_id="grant-id",
        status=GRANT_STATUS_SHADOWED,
        actor="system",
        last_synced_at=None,
        last_sync_error=None,
        event_type=EVENT_GRANT_SHADOWED,
        message="grant shadowed by tenant membership",
    )


@pytest.mark.asyncio
async def test_reconcile_tenant_membership_reactivates_unshadowed_grants(
    manager,
    store,
):
    grant = _grant(status="shadowed")
    store.list_active_grants_for_user.side_effect = [[grant], []]

    await manager.reconcile_tenant_membership("alice", "kbase", None)

    store.update_grant_status.assert_called_once_with(
        grant_id="grant-id",
        status=GRANT_STATUS_PENDING,
        actor="system",
        last_synced_at=None,
        last_sync_error=None,
        event_type=EVENT_GRANT_ACTIVATED,
        message="grant reactivated after tenant membership change",
    )


@pytest.mark.asyncio
async def test_reconcile_tenant_membership_skips_other_tenant_grants(
    manager,
    store,
):
    other_grant = NamespaceAclGrantRecord(
        id="other-grant-id",
        role_id="other-role-id",
        tenant_name="other",
        catalog_name="tenant_other",
        namespace_name="shared_data",
        namespace_parts=("shared_data",),
        username="alice",
        access_level="read",
        status="active",
        granted_by="steward",
        granted_at=NOW,
        updated_by="steward",
        updated_at=NOW,
        revoked_by=None,
        revoked_at=None,
        last_synced_at=None,
        last_sync_error=None,
    )
    store.list_active_grants_for_user.side_effect = [[other_grant], []]

    result = await manager.reconcile_tenant_membership("alice", "kbase", "read_write")

    store.update_grant_status.assert_not_called()
    assert result.success is True


@pytest.mark.asyncio
async def test_delete_tenant_cascade_revokes_grants_and_namespace_roles(
    manager,
    store,
    polaris_service,
):
    grant = _grant(status="active")
    role = _role()
    store.list_grants_for_tenant.return_value = [grant]
    store.revoke_grant.return_value = grant
    store.list_active_grants_for_user.return_value = []
    store.list_roles_for_tenant.return_value = [role]

    result = await manager.delete_tenant_cascade("kbase")

    assert result.revoked_grants == 1
    assert result.reconciled_users == ("alice",)
    assert result.deleted_principal_roles == ("namespace_acl_hash_read_member",)
    store.revoke_grant.assert_called_once_with(
        tenant_name="kbase",
        namespace_parts=("shared_data",),
        username="alice",
        actor="system",
        message="tenant 'kbase' was deleted",
    )
    polaris_service.delete_principal_role.assert_called_once_with(
        "namespace_acl_hash_read_member"
    )
    # Role rows must be dropped so a tenant recreated with the same namespace
    # can be granted again without unique-constraint conflicts.
    store.delete_roles_for_tenant.assert_called_once_with("kbase")


@pytest.mark.asyncio
async def test_revoke_namespace_access_drops_role_when_no_active_grants_remain(
    manager,
    store,
    polaris_service,
):
    """The last revocation on a (tenant, namespace, access_level) tuple should
    drop the now-unused Polaris catalog/principal roles and the role row so
    they don't accumulate over time."""
    grant = _grant(status="active")
    role = _role()
    store.revoke_grant.return_value = grant
    store.list_active_grants_for_user.return_value = []
    store.count_active_grants_for_role.return_value = 0
    store.get_role.return_value = role

    await manager.revoke_namespace_access(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        actor="steward",
    )

    store.count_active_grants_for_role.assert_called_once_with("role-id")
    polaris_service.delete_principal_role.assert_called_once_with(
        role.principal_role_name
    )
    polaris_service.delete_catalog_role.assert_called_once_with(
        role.catalog_name,
        role.catalog_role_name,
    )
    store.delete_role.assert_called_once_with(role.id)


@pytest.mark.asyncio
async def test_cleanup_orphan_role_stops_when_principal_role_delete_fails(
    manager,
    store,
    polaris_service,
):
    role = _role()
    store.count_active_grants_for_role.return_value = 0
    store.get_role.return_value = role
    polaris_service.delete_principal_role.side_effect = Exception("delete failed")

    await manager._cleanup_orphan_role("role-id")

    polaris_service.delete_principal_role.assert_called_once_with(
        role.principal_role_name
    )
    polaris_service.delete_catalog_role.assert_not_called()
    store.delete_role.assert_not_called()


@pytest.mark.asyncio
async def test_cleanup_orphan_role_stops_when_catalog_role_delete_fails(
    manager,
    store,
    polaris_service,
):
    role = _role()
    store.count_active_grants_for_role.return_value = 0
    store.get_role.return_value = role
    polaris_service.delete_catalog_role.side_effect = Exception("delete failed")

    await manager._cleanup_orphan_role("role-id")

    polaris_service.delete_principal_role.assert_called_once_with(
        role.principal_role_name
    )
    polaris_service.delete_catalog_role.assert_called_once_with(
        role.catalog_name,
        role.catalog_role_name,
    )
    store.delete_role.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_namespace_access_keeps_role_when_other_grants_remain(
    manager,
    store,
    polaris_service,
):
    """A revoke must NOT drop the Polaris/DB role when other users still have
    a grant on the same (tenant, namespace, access_level) tuple."""
    grant = _grant(status="active")
    store.revoke_grant.return_value = grant
    store.list_active_grants_for_user.return_value = []
    store.count_active_grants_for_role.return_value = 2

    await manager.revoke_namespace_access(
        tenant_name="kbase",
        namespace_parts=["shared_data"],
        username="alice",
        actor="steward",
    )

    polaris_service.delete_principal_role.assert_not_called()
    polaris_service.delete_catalog_role.assert_not_called()
    store.delete_role.assert_not_called()


@pytest.mark.asyncio
async def test_is_shadowed_by_tenant_membership_returns_true_for_rw_member(
    manager,
):
    """RW tenant membership shadows both read and write namespace ACL grants."""
    group_manager = MagicMock()
    group_manager.get_group_members = AsyncMock(return_value=["alice"])
    manager.set_group_manager(group_manager)

    assert (
        await manager.is_shadowed_by_tenant_membership(
            tenant_name="kbase",
            username="alice",
            access_level="write",
        )
        is True
    )


@pytest.mark.asyncio
async def test_is_shadowed_by_tenant_membership_does_not_shadow_write_for_ro_member(
    manager,
):
    """RO tenant membership shadows read grants but not write grants."""
    group_manager = MagicMock()
    group_manager.get_group_members = AsyncMock(side_effect=[[], ["alice"]])
    manager.set_group_manager(group_manager)

    assert (
        await manager.is_shadowed_by_tenant_membership(
            tenant_name="kbase",
            username="alice",
            access_level="write",
        )
        is False
    )


@pytest.mark.asyncio
async def test_is_shadowed_by_tenant_membership_shadows_read_for_ro_member(
    manager,
):
    group_manager = MagicMock()
    group_manager.get_group_members = AsyncMock(side_effect=[[], ["alice"]])
    manager.set_group_manager(group_manager)

    assert (
        await manager.is_shadowed_by_tenant_membership(
            tenant_name="kbase",
            username="alice",
            access_level="read",
        )
        is True
    )


@pytest.mark.asyncio
async def test_is_shadowed_by_tenant_membership_returns_false_when_no_group_manager(
    manager,
):
    """Without a GroupManager wired in, the manager must default to no-shadow
    rather than crash. App startup wires it; this is a safety belt."""
    assert (
        await manager.is_shadowed_by_tenant_membership(
            tenant_name="kbase",
            username="alice",
            access_level="read",
        )
        is False
    )


@pytest.mark.asyncio
async def test_delete_user_cascade_revokes_user_grants(
    manager,
    store,
    policy_manager,
):
    grant = _grant(status="active")
    store.list_active_grants_for_user.side_effect = [[grant], []]
    store.revoke_grant.return_value = grant

    result = await manager.delete_user_cascade("alice")

    assert result.revoked_grants == 1
    assert result.reconciled_users == ("alice",)
    assert result.deleted_principal_roles == ()
    store.revoke_grant.assert_called_once_with(
        tenant_name="kbase",
        namespace_parts=("shared_data",),
        username="alice",
        actor="system",
        message="user 'alice' was deleted",
    )
    policy_manager.detach_and_delete_user_policy.assert_called_once_with(
        "namespace-acl-alice",
        "alice",
    )


@pytest.mark.asyncio
async def test_delete_user_cascade_counts_only_revoked_grants(manager, store):
    grant = _grant(status="active")
    store.list_active_grants_for_user.side_effect = [[grant], []]
    store.revoke_grant.return_value = None

    result = await manager.delete_user_cascade("alice")

    assert result.revoked_grants == 0
