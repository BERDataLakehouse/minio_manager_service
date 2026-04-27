"""Tests for Polaris namespace ACL persistence helpers."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from polaris.namespace_acl_store import (
    EVENT_ACCESS_LEVEL_CHANGED,
    EVENT_GRANT_ACTIVATED,
    EVENT_GRANT_CREATED,
    EVENT_GRANT_IDEMPOTENT,
    EVENT_GRANT_REVOKED,
    EVENT_GRANT_SHADOWED,
    EVENT_SYNC_FAILED,
    EVENT_SYNC_HEALED,
    EVENT_VALIDATION_FAILED,
    GRANT_STATUS_ACTIVE,
    GRANT_STATUS_PENDING,
    GRANT_STATUS_SHADOWED,
    GRANT_STATUS_SYNC_ERROR,
    MAX_POLARIS_ROLE_NAME_LENGTH,
    NAMESPACE_ACL_ROLE_PREFIX,
    NamespaceAclRoleCollisionError,
    NamespaceAclStore,
    _create_event_type,
    _status_event_type,
    _update_event_type,
    build_namespace_acl_role_names,
    namespace_name_from_parts,
    normalize_access_level,
    normalize_event_type,
    normalize_grant_status,
    normalize_namespace_parts,
    tenant_catalog_name,
)


NOW = datetime(2026, 4, 26, tzinfo=UTC)


def _cursor(row=None, rows=None):
    mock_cursor = AsyncMock()
    mock_cursor.fetchone = AsyncMock(return_value=row)
    mock_cursor.fetchall = AsyncMock(return_value=rows or [])
    return mock_cursor


def _role_row(
    role_id="role-id",
    tenant_name="kbase",
    namespace_name="shared_data",
    namespace_parts=None,
    access_level="read",
    hash_len=24,
):
    namespace_parts = namespace_parts or ["shared_data"]
    role_names = build_namespace_acl_role_names(
        tenant_name,
        namespace_parts,
        access_level,
        hash_len=hash_len,
    )
    return (
        role_id,
        tenant_name,
        tenant_catalog_name(tenant_name),
        namespace_name,
        namespace_parts,
        access_level,
        role_names.catalog_role_name,
        role_names.principal_role_name,
        hash_len,
        NOW,
        NOW,
    )


def _grant_row(
    grant_id="grant-id",
    role_id="role-id",
    tenant_name="kbase",
    namespace_name="shared_data",
    namespace_parts=None,
    username="alice",
    access_level="read",
    status="pending",
    granted_by="steward",
    updated_by="steward",
    revoked_by=None,
    revoked_at=None,
    last_synced_at=None,
    last_sync_error=None,
):
    namespace_parts = namespace_parts or ["shared_data"]
    return (
        grant_id,
        role_id,
        tenant_name,
        tenant_catalog_name(tenant_name),
        namespace_name,
        namespace_parts,
        username,
        access_level,
        status,
        granted_by,
        NOW,
        updated_by,
        NOW,
        revoked_by,
        revoked_at,
        last_synced_at,
        last_sync_error,
    )


@pytest.fixture
def mock_pool():
    """Create a mock AsyncConnectionPool."""
    pool = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.commit = AsyncMock()

    class MockConnectionCM:
        async def __aenter__(self):
            return mock_conn

        async def __aexit__(self, *args):
            pass

    pool.connection = MockConnectionCM
    pool._mock_conn = mock_conn
    return pool


@pytest.fixture
def store(mock_pool):
    """Create a NamespaceAclStore with a mocked pool."""
    return NamespaceAclStore(mock_pool)


class TestNamespaceAclNormalization:
    """Tests for namespace ACL helper functions."""

    def test_tenant_catalog_name(self):
        assert tenant_catalog_name("kbase") == "tenant_kbase"

    def test_tenant_catalog_name_rejects_empty_tenant(self):
        with pytest.raises(ValueError, match="tenant_name"):
            tenant_catalog_name("")

    def test_normalize_access_level(self):
        assert normalize_access_level(" READ ") == "read"
        assert normalize_access_level("write") == "write"

    def test_normalize_access_level_rejects_invalid_value(self):
        with pytest.raises(ValueError, match="access_level"):
            normalize_access_level("admin")

    def test_normalize_grant_status_rejects_invalid_value(self):
        with pytest.raises(ValueError, match="status must be"):
            normalize_grant_status("broken")

    def test_normalize_event_type(self):
        assert normalize_event_type(" VALIDATION_FAILED ") == EVENT_VALIDATION_FAILED

    def test_normalize_event_type_rejects_invalid_value(self):
        with pytest.raises(ValueError, match="unsupported"):
            normalize_event_type("broken")

    def test_normalize_namespace_parts(self):
        assert normalize_namespace_parts([" geo ", "curated"]) == ("geo", "curated")
        assert namespace_name_from_parts(["geo", "curated"]) == "geo.curated"

    def test_normalize_namespace_parts_rejects_empty_sequence(self):
        with pytest.raises(ValueError, match="must not be empty"):
            normalize_namespace_parts([])

    def test_normalize_namespace_parts_rejects_dotted_string(self):
        with pytest.raises(ValueError, match="not a dotted string"):
            normalize_namespace_parts("geo.curated")

    def test_normalize_namespace_parts_rejects_empty_values(self):
        with pytest.raises(ValueError, match="empty"):
            normalize_namespace_parts(["geo", ""])

    def test_normalize_namespace_parts_rejects_dotted_values(self):
        with pytest.raises(ValueError, match="dotted values"):
            normalize_namespace_parts(["geo.curated"])

    def test_normalize_namespace_parts_rejects_wildcards_and_path_separators(self):
        with pytest.raises(ValueError, match="letters, numbers"):
            normalize_namespace_parts(["shared*"])
        with pytest.raises(ValueError, match="letters, numbers"):
            normalize_namespace_parts(["geo/curated"])

    def test_normalize_namespace_parts_rejects_non_ascii(self):
        with pytest.raises(ValueError, match="ASCII"):
            normalize_namespace_parts(["café"])

    def test_normalize_namespace_parts_rejects_overlong_part(self):
        # Polaris/Iceberg cap individual identifier components at 256 chars; we
        # reject overlong inputs locally to surface a useful error before the
        # round-trip to Polaris.
        too_long = "a" * 257
        with pytest.raises(ValueError, match="at most 256 characters"):
            normalize_namespace_parts([too_long])

    def test_role_names_are_deterministic_sha256_hashes(self):
        role_names = build_namespace_acl_role_names(
            "kbase",
            ["shared_data"],
            "read",
        )

        assert (
            role_names.catalog_role_name
            == "namespace_acl_ebbbe89897eb3e1780f339c1_read"
        )
        assert (
            role_names.principal_role_name
            == "namespace_acl_ebbbe89897eb3e1780f339c1_read_member"
        )
        assert role_names.role_name_hash_len == 24

    def test_role_name_rejects_invalid_hash_length(self):
        with pytest.raises(ValueError, match="hash_len"):
            build_namespace_acl_role_names("kbase", ["shared_data"], "read", hash_len=8)

    def test_role_name_rejects_catalog_name_over_length(self, monkeypatch):
        monkeypatch.setattr(
            "polaris.namespace_acl_store.NAMESPACE_ACL_ROLE_PREFIX",
            "x" * MAX_POLARIS_ROLE_NAME_LENGTH,
        )

        with pytest.raises(ValueError, match="catalog role name"):
            build_namespace_acl_role_names("kbase", ["shared_data"], "read")

    def test_role_name_rejects_principal_name_over_length(self, monkeypatch):
        prefix_len = (
            MAX_POLARIS_ROLE_NAME_LENGTH
            - len(NAMESPACE_ACL_ROLE_PREFIX)
            - 24
            - len("_read")
        )
        monkeypatch.setattr(
            "polaris.namespace_acl_store.NAMESPACE_ACL_ROLE_PREFIX",
            f"{NAMESPACE_ACL_ROLE_PREFIX}{'x' * prefix_len}",
        )

        with pytest.raises(ValueError, match="principal role name"):
            build_namespace_acl_role_names("kbase", ["shared_data"], "read")

    def test_event_type_helpers(self):
        assert _create_event_type(GRANT_STATUS_SHADOWED) == EVENT_GRANT_SHADOWED
        assert (
            _update_event_type("read", "pending", "read", GRANT_STATUS_SHADOWED)
            == EVENT_GRANT_SHADOWED
        )
        assert (
            _update_event_type("read", "pending", "read", GRANT_STATUS_ACTIVE)
            == EVENT_GRANT_ACTIVATED
        )
        assert (
            _update_event_type("read", "active", "write", GRANT_STATUS_ACTIVE)
            == EVENT_ACCESS_LEVEL_CHANGED
        )
        assert (
            _update_event_type("read", "active", "read", GRANT_STATUS_ACTIVE)
            == EVENT_GRANT_IDEMPOTENT
        )
        assert _status_event_type(GRANT_STATUS_ACTIVE) == EVENT_SYNC_HEALED
        assert _status_event_type(GRANT_STATUS_SYNC_ERROR) == EVENT_SYNC_FAILED
        assert _status_event_type(GRANT_STATUS_SHADOWED) == EVENT_GRANT_SHADOWED
        assert _status_event_type(GRANT_STATUS_PENDING) == EVENT_GRANT_IDEMPOTENT


class TestNamespaceAclStoreEnsureRole:
    """Tests for ensure_role."""

    @pytest.mark.asyncio
    async def test_returns_existing_role(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(row=_role_row())

        role = await store.ensure_role("kbase", ["shared_data"], "read")

        assert role.id == "role-id"
        assert role.tenant_name == "kbase"
        assert role.catalog_name == "tenant_kbase"
        assert role.namespace_name == "shared_data"
        assert role.namespace_parts == ("shared_data",)
        assert role.access_level == "read"
        mock_pool._mock_conn.execute.assert_called_once()
        mock_pool._mock_conn.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_inserts_missing_role(self, store, mock_pool):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=None),
            _cursor(row=_role_row()),
        ]

        role = await store.ensure_role("kbase", ["shared_data"], "read")

        assert role.id == "role-id"
        assert role.catalog_role_name == "namespace_acl_ebbbe89897eb3e1780f339c1_read"
        assert role.principal_role_name.endswith("_member")
        assert role.role_name_hash_len == 24
        assert mock_pool._mock_conn.execute.call_count == 2
        mock_pool._mock_conn.commit.assert_called_once()

        insert_params = mock_pool._mock_conn.execute.call_args_list[1].args[1]
        assert insert_params["tenant_name"] == "kbase"
        assert insert_params["catalog_name"] == "tenant_kbase"
        assert insert_params["namespace_name"] == "shared_data"
        assert insert_params["namespace_parts"] == ["shared_data"]
        assert insert_params["access_level"] == "read"

    @pytest.mark.asyncio
    async def test_retries_with_longer_hash_after_role_name_collision(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=_role_row(hash_len=32)),
        ]

        role = await store.ensure_role("kbase", ["shared_data"], "read")

        assert role.role_name_hash_len == 32
        assert len(role.catalog_role_name) == len("namespace_acl__read") + 32
        assert mock_pool._mock_conn.execute.call_count == 4

    @pytest.mark.asyncio
    async def test_returns_existing_role_after_concurrent_insert(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=_role_row()),
        ]

        role = await store.ensure_role("kbase", ["shared_data"], "read")

        assert role.id == "role-id"
        mock_pool._mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_when_all_role_name_hash_lengths_collide(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=None),
            _cursor(row=None),
        ]

        with pytest.raises(NamespaceAclRoleCollisionError):
            await store.ensure_role("kbase", ["shared_data"], "read")


class TestNamespaceAclStoreGrantMutations:
    """Tests for create/update/revoke grant behavior."""

    @pytest.mark.asyncio
    async def test_create_or_update_grant_inserts_new_grant(self, store, mock_pool):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=None),
            _cursor(row=_role_row()),
            _cursor(row=None),
            _cursor(row=_grant_row()),
            _cursor(row=None),
        ]

        mutation = await store.create_or_update_grant(
            tenant_name="kbase",
            namespace_parts=["shared_data"],
            username="alice",
            access_level="read",
            actor="steward",
        )

        assert mutation.created is True
        assert mutation.event_type == EVENT_GRANT_CREATED
        assert mutation.grant.id == "grant-id"
        assert mutation.grant.status == GRANT_STATUS_PENDING
        assert mock_pool._mock_conn.execute.call_count == 5
        assert mock_pool._mock_conn.commit.call_count == 2

        event_params = mock_pool._mock_conn.execute.call_args_list[-1].args[1]
        assert event_params["event_type"] == EVENT_GRANT_CREATED
        assert event_params["grant_id"] == "grant-id"
        assert event_params["username"] == "alice"

    @pytest.mark.asyncio
    async def test_create_or_update_grant_records_idempotent_event(
        self, store, mock_pool
    ):
        existing_grant = _grant_row()
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=_role_row()),
            _cursor(row=existing_grant),
            _cursor(row=None),
        ]

        mutation = await store.create_or_update_grant(
            tenant_name="kbase",
            namespace_parts=["shared_data"],
            username="alice",
            access_level="read",
            actor="steward",
        )

        assert mutation.created is False
        assert mutation.event_type == EVENT_GRANT_IDEMPOTENT
        assert mutation.previous_access_level == "read"
        assert mutation.previous_status == GRANT_STATUS_PENDING
        assert mock_pool._mock_conn.execute.call_count == 3

    @pytest.mark.asyncio
    async def test_create_or_update_grant_updates_access_level(self, store, mock_pool):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=_role_row(access_level="write")),
            _cursor(row=_grant_row(access_level="read")),
            _cursor(row=_grant_row(access_level="write", status=GRANT_STATUS_ACTIVE)),
            _cursor(row=None),
        ]

        mutation = await store.create_or_update_grant(
            tenant_name="kbase",
            namespace_parts=["shared_data"],
            username="alice",
            access_level="write",
            actor="steward",
            status=GRANT_STATUS_ACTIVE,
        )

        assert mutation.created is False
        assert mutation.event_type == EVENT_ACCESS_LEVEL_CHANGED
        assert mutation.grant.access_level == "write"
        assert mutation.grant.status == GRANT_STATUS_ACTIVE

        update_params = mock_pool._mock_conn.execute.call_args_list[2].args[1]
        assert update_params["access_level"] == "write"
        assert update_params["status"] == GRANT_STATUS_ACTIVE

    @pytest.mark.asyncio
    async def test_revoke_grant_marks_active_row_revoked(self, store, mock_pool):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=_grant_row(status=GRANT_STATUS_ACTIVE)),
            _cursor(
                row=_grant_row(
                    status="revoked",
                    revoked_by="steward",
                    revoked_at=NOW,
                )
            ),
            _cursor(row=None),
        ]

        grant = await store.revoke_grant(
            tenant_name="kbase",
            namespace_parts=["shared_data"],
            username="alice",
            actor="steward",
        )

        assert grant is not None
        assert grant.status == "revoked"
        assert grant.revoked_by == "steward"
        assert mock_pool._mock_conn.execute.call_count == 3
        mock_pool._mock_conn.commit.assert_called_once()

        event_params = mock_pool._mock_conn.execute.call_args_list[-1].args[1]
        assert event_params["event_type"] == EVENT_GRANT_REVOKED
        assert event_params["old_status"] == GRANT_STATUS_ACTIVE
        assert event_params["new_status"] == "revoked"

    @pytest.mark.asyncio
    async def test_revoke_grant_returns_none_when_no_active_grant(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.return_value = _cursor(row=None)

        grant = await store.revoke_grant(
            tenant_name="kbase",
            namespace_parts=["shared_data"],
            username="alice",
            actor="steward",
        )

        assert grant is None
        mock_pool._mock_conn.execute.assert_called_once()
        mock_pool._mock_conn.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_active_grant_returns_none_when_missing(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(row=None)

        grant = await store.get_active_grant("kbase", ["shared_data"], "alice")

        assert grant is None
        mock_pool._mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_active_grant_returns_record(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(row=_grant_row())

        grant = await store.get_active_grant("kbase", ["shared_data"], "alice")

        assert grant is not None
        assert grant.id == "grant-id"
        assert grant.username == "alice"

    @pytest.mark.asyncio
    async def test_get_role_returns_none_when_missing(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(row=None)

        role = await store.get_role("role-id")

        assert role is None

    @pytest.mark.asyncio
    async def test_get_role_returns_record(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(row=_role_row())

        role = await store.get_role("role-id")

        assert role is not None
        assert role.id == "role-id"

    @pytest.mark.asyncio
    async def test_list_roles_for_tenant(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(rows=[_role_row()])

        roles = await store.list_roles_for_tenant("kbase")

        assert len(roles) == 1
        assert roles[0].tenant_name == "kbase"

    @pytest.mark.asyncio
    async def test_count_active_grants_for_role_returns_count(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(row=(3,))

        count = await store.count_active_grants_for_role("role-id")

        assert count == 3
        mock_pool._mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_count_active_grants_for_role_returns_zero_without_row(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.return_value = _cursor(row=None)

        assert await store.count_active_grants_for_role("role-id") == 0

    @pytest.mark.asyncio
    async def test_delete_role_returns_rowcount(self, store, mock_pool):
        cursor = _cursor()
        cursor.rowcount = 1
        mock_pool._mock_conn.execute.return_value = cursor

        assert await store.delete_role("role-id") is True
        mock_pool._mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_roles_for_tenant_returns_rowcount(self, store, mock_pool):
        cursor = _cursor()
        cursor.rowcount = 2
        mock_pool._mock_conn.execute.return_value = cursor

        assert await store.delete_roles_for_tenant("kbase") == 2
        mock_pool._mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_grants_for_tenant_with_namespace_filter(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(rows=[_grant_row()])

        grants = await store.list_grants_for_tenant("kbase", ["shared_data"])

        assert len(grants) == 1
        params = mock_pool._mock_conn.execute.call_args.args[1]
        assert params["namespace_name"] == "shared_data"

    @pytest.mark.asyncio
    async def test_list_active_grants_for_user_normalizes_statuses(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.return_value = _cursor(rows=[_grant_row()])

        grants = await store.list_active_grants_for_user(
            "alice",
            statuses=[" ACTIVE ", "sync_error"],
        )

        assert len(grants) == 1
        params = mock_pool._mock_conn.execute.call_args.args[1]
        assert params["statuses"] == [GRANT_STATUS_ACTIVE, GRANT_STATUS_SYNC_ERROR]

    @pytest.mark.asyncio
    async def test_list_usernames_for_sync_filters_statuses_and_tenant(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.return_value = _cursor(rows=[("alice",), ("bob",)])

        usernames = await store.list_usernames_for_sync(
            tenant_name="kbase",
            statuses=["active", " sync_error "],
        )

        assert usernames == ["alice", "bob"]
        params = mock_pool._mock_conn.execute.call_args.args[1]
        assert params["tenant_name"] == "kbase"
        assert params["statuses"] == [GRANT_STATUS_ACTIVE, GRANT_STATUS_SYNC_ERROR]

    @pytest.mark.asyncio
    async def test_update_grant_status_returns_none_when_row_missing(
        self, store, mock_pool
    ):
        mock_pool._mock_conn.execute.return_value = _cursor(row=None)

        grant = await store.update_grant_status(
            "grant-id",
            GRANT_STATUS_ACTIVE,
        )

        assert grant is None
        mock_pool._mock_conn.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_grant_status_appends_default_event(self, store, mock_pool):
        mock_pool._mock_conn.execute.side_effect = [
            _cursor(row=_grant_row(status=GRANT_STATUS_ACTIVE)),
            _cursor(row=None),
        ]

        grant = await store.update_grant_status(
            "grant-id",
            GRANT_STATUS_ACTIVE,
            actor="system",
            last_synced_at=NOW,
            last_sync_error=None,
            message="healed",
        )

        assert grant is not None
        assert grant.status == GRANT_STATUS_ACTIVE
        event_params = mock_pool._mock_conn.execute.call_args_list[-1].args[1]
        assert event_params["event_type"] == EVENT_SYNC_HEALED
        assert event_params["message"] == "healed"
        mock_pool._mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_append_event_without_grant_row(self, store, mock_pool):
        mock_pool._mock_conn.execute.return_value = _cursor(row=None)

        await store.append_event(
            tenant_name="kbase",
            namespace_parts=["shared_data"],
            event_type=EVENT_VALIDATION_FAILED,
            actor="steward",
            username="alice",
            message="invalid namespace",
        )

        params = mock_pool._mock_conn.execute.call_args.args[1]
        assert params["grant_id"] is None
        assert params["namespace_name"] == "shared_data"
        assert params["event_type"] == EVENT_VALIDATION_FAILED
        mock_pool._mock_conn.commit.assert_called_once()
