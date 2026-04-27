"""PostgreSQL store for Polaris namespace ACL grants."""

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Sequence

from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

AccessLevel = Literal["read", "write"]
GrantStatus = Literal["pending", "active", "shadowed", "sync_error", "revoked"]
EventType = Literal[
    "grant_created",
    "grant_idempotent",
    "access_level_changed",
    "grant_shadowed",
    "grant_activated",
    "grant_revoked",
    "sync_started",
    "sync_failed",
    "sync_healed",
    "validation_failed",
]

ACCESS_LEVEL_READ: AccessLevel = "read"
ACCESS_LEVEL_WRITE: AccessLevel = "write"
GRANT_STATUS_PENDING: GrantStatus = "pending"
GRANT_STATUS_ACTIVE: GrantStatus = "active"
GRANT_STATUS_SHADOWED: GrantStatus = "shadowed"
GRANT_STATUS_SYNC_ERROR: GrantStatus = "sync_error"
GRANT_STATUS_REVOKED: GrantStatus = "revoked"

EVENT_GRANT_CREATED: EventType = "grant_created"
EVENT_GRANT_IDEMPOTENT: EventType = "grant_idempotent"
EVENT_ACCESS_LEVEL_CHANGED: EventType = "access_level_changed"
EVENT_GRANT_SHADOWED: EventType = "grant_shadowed"
EVENT_GRANT_ACTIVATED: EventType = "grant_activated"
EVENT_GRANT_REVOKED: EventType = "grant_revoked"
EVENT_SYNC_STARTED: EventType = "sync_started"
EVENT_SYNC_FAILED: EventType = "sync_failed"
EVENT_SYNC_HEALED: EventType = "sync_healed"
EVENT_VALIDATION_FAILED: EventType = "validation_failed"

MAX_POLARIS_ROLE_NAME_LENGTH = 256
NAMESPACE_ACL_ROLE_HASH_LENGTHS = (24, 32, 40)
NAMESPACE_ACL_ROLE_PREFIX = "namespace_acl_"
TENANT_CATALOG_PREFIX = "tenant_"
# Polaris/Iceberg cap individual identifier components at 256 characters.
MAX_NAMESPACE_PART_LENGTH = 256
NAMESPACE_PART_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

_ACCESS_LEVELS = {ACCESS_LEVEL_READ, ACCESS_LEVEL_WRITE}
_GRANT_STATUSES = {
    GRANT_STATUS_PENDING,
    GRANT_STATUS_ACTIVE,
    GRANT_STATUS_SHADOWED,
    GRANT_STATUS_SYNC_ERROR,
    GRANT_STATUS_REVOKED,
}
_EVENT_TYPES = {
    EVENT_GRANT_CREATED,
    EVENT_GRANT_IDEMPOTENT,
    EVENT_ACCESS_LEVEL_CHANGED,
    EVENT_GRANT_SHADOWED,
    EVENT_GRANT_ACTIVATED,
    EVENT_GRANT_REVOKED,
    EVENT_SYNC_STARTED,
    EVENT_SYNC_FAILED,
    EVENT_SYNC_HEALED,
    EVENT_VALIDATION_FAILED,
}

_ROLE_COLUMNS = """
id,
tenant_name,
catalog_name,
namespace_name,
namespace_parts,
access_level,
catalog_role_name,
principal_role_name,
role_name_hash_len,
created_at,
updated_at
"""

_GRANT_COLUMNS = """
id,
role_id,
tenant_name,
catalog_name,
namespace_name,
namespace_parts,
username,
access_level,
status,
granted_by,
granted_at,
updated_by,
updated_at,
revoked_by,
revoked_at,
last_synced_at,
last_sync_error
"""

_SELECT_ROLE_BY_TUPLE = f"""
SELECT {_ROLE_COLUMNS}
  FROM polaris_namespace_acl_roles
 WHERE tenant_name = %(tenant_name)s
   AND namespace_name = %(namespace_name)s
   AND access_level = %(access_level)s;
"""

_SELECT_ROLE_BY_ID = f"""
SELECT {_ROLE_COLUMNS}
  FROM polaris_namespace_acl_roles
 WHERE id = %(role_id)s;
"""

_LIST_ROLES_FOR_TENANT = f"""
SELECT {_ROLE_COLUMNS}
  FROM polaris_namespace_acl_roles
 WHERE tenant_name = %(tenant_name)s
 ORDER BY namespace_name, access_level;
"""

_COUNT_ACTIVE_GRANTS_FOR_ROLE = """
SELECT COUNT(1)
  FROM polaris_namespace_acl_grants
 WHERE role_id = %(role_id)s
   AND revoked_at IS NULL;
"""

_DELETE_ROLE = """
DELETE FROM polaris_namespace_acl_roles
 WHERE id = %(role_id)s;
"""

_DELETE_ROLES_FOR_TENANT = """
DELETE FROM polaris_namespace_acl_roles
 WHERE tenant_name = %(tenant_name)s;
"""

_DELETE_GRANTS_FOR_TENANT = """
DELETE FROM polaris_namespace_acl_grants
 WHERE tenant_name = %(tenant_name)s;
"""

_DELETE_EVENTS_FOR_TENANT = """
DELETE FROM polaris_namespace_acl_events
 WHERE tenant_name = %(tenant_name)s;
"""

_INSERT_ROLE = f"""
INSERT INTO polaris_namespace_acl_roles (
    tenant_name,
    catalog_name,
    namespace_name,
    namespace_parts,
    access_level,
    catalog_role_name,
    principal_role_name,
    role_name_hash_len
)
VALUES (
    %(tenant_name)s,
    %(catalog_name)s,
    %(namespace_name)s,
    %(namespace_parts)s,
    %(access_level)s,
    %(catalog_role_name)s,
    %(principal_role_name)s,
    %(role_name_hash_len)s
)
ON CONFLICT DO NOTHING
RETURNING {_ROLE_COLUMNS};
"""

_SELECT_ACTIVE_GRANT = f"""
SELECT {_GRANT_COLUMNS}
  FROM polaris_namespace_acl_grants
 WHERE tenant_name = %(tenant_name)s
   AND namespace_name = %(namespace_name)s
   AND username = %(username)s
   AND revoked_at IS NULL;
"""

_SELECT_ACTIVE_GRANT_FOR_UPDATE = f"""
SELECT {_GRANT_COLUMNS}
  FROM polaris_namespace_acl_grants
 WHERE tenant_name = %(tenant_name)s
   AND namespace_name = %(namespace_name)s
   AND username = %(username)s
   AND revoked_at IS NULL
 FOR UPDATE;
"""

_INSERT_GRANT = f"""
INSERT INTO polaris_namespace_acl_grants (
    role_id,
    tenant_name,
    catalog_name,
    namespace_name,
    namespace_parts,
    username,
    access_level,
    status,
    granted_by,
    updated_by
)
VALUES (
    %(role_id)s,
    %(tenant_name)s,
    %(catalog_name)s,
    %(namespace_name)s,
    %(namespace_parts)s,
    %(username)s,
    %(access_level)s,
    %(status)s,
    %(actor)s,
    %(actor)s
)
RETURNING {_GRANT_COLUMNS};
"""

_UPDATE_GRANT = f"""
UPDATE polaris_namespace_acl_grants
   SET role_id = %(role_id)s,
       access_level = %(access_level)s,
       status = %(status)s,
       updated_by = %(actor)s,
       updated_at = now(),
       last_sync_error = NULL
 WHERE id = %(grant_id)s
RETURNING {_GRANT_COLUMNS};
"""

_REVOKE_GRANT = f"""
UPDATE polaris_namespace_acl_grants
   SET status = 'revoked',
       revoked_by = %(actor)s,
       revoked_at = now(),
       updated_by = %(actor)s,
       updated_at = now()
 WHERE id = %(grant_id)s
   AND revoked_at IS NULL
RETURNING {_GRANT_COLUMNS};
"""

_LIST_GRANTS_FOR_TENANT = f"""
SELECT {_GRANT_COLUMNS}
  FROM polaris_namespace_acl_grants
 WHERE tenant_name = %(tenant_name)s
   AND (%(namespace_name)s::text IS NULL OR namespace_name = %(namespace_name)s::text)
 ORDER BY namespace_name, username, granted_at;
"""

_LIST_ACTIVE_GRANTS_FOR_USER = f"""
SELECT {_GRANT_COLUMNS}
  FROM polaris_namespace_acl_grants
 WHERE username = %(username)s
   AND revoked_at IS NULL
   AND status = ANY(%(statuses)s)
 ORDER BY tenant_name, namespace_name, access_level;
"""

_LIST_USERNAMES_FOR_SYNC = """
SELECT DISTINCT username
  FROM polaris_namespace_acl_grants
 WHERE revoked_at IS NULL
   AND status = ANY(%(statuses)s)
   AND (%(tenant_name)s::text IS NULL OR tenant_name = %(tenant_name)s::text)
 ORDER BY username;
"""

_UPDATE_GRANT_STATUS = f"""
UPDATE polaris_namespace_acl_grants
   SET status = %(status)s,
       updated_by = %(actor)s,
       updated_at = now(),
       last_synced_at = %(last_synced_at)s,
       last_sync_error = %(last_sync_error)s
 WHERE id = %(grant_id)s
   AND revoked_at IS NULL
RETURNING {_GRANT_COLUMNS};
"""

_INSERT_EVENT = """
INSERT INTO polaris_namespace_acl_events (
    grant_id,
    tenant_name,
    namespace_name,
    username,
    event_type,
    old_access_level,
    new_access_level,
    old_status,
    new_status,
    actor,
    message
)
VALUES (
    %(grant_id)s,
    %(tenant_name)s,
    %(namespace_name)s,
    %(username)s,
    %(event_type)s,
    %(old_access_level)s,
    %(new_access_level)s,
    %(old_status)s,
    %(new_status)s,
    %(actor)s,
    %(message)s
);
"""


class NamespaceAclRoleCollisionError(RuntimeError):
    """Raised when all configured namespace ACL role hash lengths collide."""


@dataclass(frozen=True)
class NamespaceAclRoleNames:
    """Deterministic Polaris role names for one namespace ACL scope."""

    catalog_role_name: str
    principal_role_name: str
    role_name_hash_len: int


@dataclass(frozen=True)
class NamespaceAclRoleRecord:
    """Stored namespace ACL role metadata."""

    id: str
    tenant_name: str
    catalog_name: str
    namespace_name: str
    namespace_parts: tuple[str, ...]
    access_level: AccessLevel
    catalog_role_name: str
    principal_role_name: str
    role_name_hash_len: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class NamespaceAclGrantRecord:
    """Stored namespace ACL grant state."""

    id: str
    role_id: str
    tenant_name: str
    catalog_name: str
    namespace_name: str
    namespace_parts: tuple[str, ...]
    username: str
    access_level: AccessLevel
    status: GrantStatus
    granted_by: str
    granted_at: datetime
    updated_by: str
    updated_at: datetime
    revoked_by: str | None
    revoked_at: datetime | None
    last_synced_at: datetime | None
    last_sync_error: str | None


@dataclass(frozen=True)
class NamespaceAclGrantMutation:
    """Result of creating or changing a grant row."""

    grant: NamespaceAclGrantRecord
    created: bool
    event_type: EventType
    previous_access_level: AccessLevel | None = None
    previous_status: GrantStatus | None = None


def tenant_catalog_name(tenant_name: str) -> str:
    """Return the Polaris tenant catalog name for a base tenant name."""
    if not tenant_name:
        raise ValueError("tenant_name is required")
    return f"{TENANT_CATALOG_PREFIX}{tenant_name}"


def normalize_access_level(access_level: str) -> AccessLevel:
    """Validate and normalize namespace ACL access level."""
    normalized = access_level.strip().lower()
    if normalized not in _ACCESS_LEVELS:
        raise ValueError("access_level must be 'read' or 'write'")
    return normalized  # type: ignore[return-value]


def normalize_grant_status(status: str) -> GrantStatus:
    """Validate and normalize namespace ACL grant status."""
    normalized = status.strip().lower()
    if normalized not in _GRANT_STATUSES:
        raise ValueError(
            "status must be one of: active, pending, revoked, shadowed, sync_error"
        )
    return normalized  # type: ignore[return-value]


def normalize_event_type(event_type: str) -> EventType:
    """Validate and normalize namespace ACL event type."""
    normalized = event_type.strip().lower()
    if normalized not in _EVENT_TYPES:
        raise ValueError("unsupported namespace ACL event type")
    return normalized  # type: ignore[return-value]


def normalize_namespace_parts(namespace_parts: Sequence[str]) -> tuple[str, ...]:
    """Validate namespace parts and return a canonical tuple."""
    if isinstance(namespace_parts, str):
        raise ValueError("namespace_parts must be a sequence, not a dotted string")

    normalized = tuple(part.strip() for part in namespace_parts)
    if not normalized:
        raise ValueError("namespace_parts must not be empty")
    if any(not part for part in normalized):
        raise ValueError("namespace_parts must not contain empty values")
    if any("." in part for part in normalized):
        raise ValueError("namespace_parts must not contain dotted values")
    if any(not part.isascii() for part in normalized):
        raise ValueError("namespace parts must use ASCII identifier characters")
    if any(NAMESPACE_PART_PATTERN.fullmatch(part) is None for part in normalized):
        raise ValueError(
            "namespace parts can only contain letters, numbers, underscores, and hyphens"
        )
    if any(len(part) > MAX_NAMESPACE_PART_LENGTH for part in normalized):
        raise ValueError(
            f"namespace parts must each be at most {MAX_NAMESPACE_PART_LENGTH} characters"
        )
    return normalized


def namespace_name_from_parts(namespace_parts: Sequence[str]) -> str:
    """Return the dot-delimited namespace name used for query filters."""
    return ".".join(normalize_namespace_parts(namespace_parts))


def build_namespace_acl_role_names(
    tenant_name: str,
    namespace_parts: Sequence[str],
    access_level: str,
    hash_len: int = NAMESPACE_ACL_ROLE_HASH_LENGTHS[0],
) -> NamespaceAclRoleNames:
    """Build deterministic Polaris role names for a namespace ACL role."""
    if hash_len not in NAMESPACE_ACL_ROLE_HASH_LENGTHS:
        raise ValueError("hash_len must be one of 24, 32, or 40")

    normalized_access = normalize_access_level(access_level)
    normalized_namespace = normalize_namespace_parts(namespace_parts)
    canonical = json.dumps(
        {
            "access_level": normalized_access,
            "namespace": list(normalized_namespace),
            "tenant": tenant_name,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    catalog_role_name = (
        f"{NAMESPACE_ACL_ROLE_PREFIX}{digest[:hash_len]}_{normalized_access}"
    )
    principal_role_name = f"{catalog_role_name}_member"

    if len(catalog_role_name) > MAX_POLARIS_ROLE_NAME_LENGTH:
        raise ValueError("catalog role name exceeds Polaris length limit")
    if len(principal_role_name) > MAX_POLARIS_ROLE_NAME_LENGTH:
        raise ValueError("principal role name exceeds Polaris length limit")

    return NamespaceAclRoleNames(
        catalog_role_name=catalog_role_name,
        principal_role_name=principal_role_name,
        role_name_hash_len=hash_len,
    )


class NamespaceAclStore:
    """Async PostgreSQL store for Polaris namespace ACL state."""

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

    async def ensure_role(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        access_level: str,
    ) -> NamespaceAclRoleRecord:
        """Return or create role metadata for a tenant namespace access level."""
        normalized_access = normalize_access_level(access_level)
        normalized_namespace = normalize_namespace_parts(namespace_parts)
        namespace_name = namespace_name_from_parts(normalized_namespace)
        catalog_name = tenant_catalog_name(tenant_name)
        base_params = {
            "tenant_name": tenant_name,
            "catalog_name": catalog_name,
            "namespace_name": namespace_name,
            "namespace_parts": list(normalized_namespace),
            "access_level": normalized_access,
        }

        async with self._pool.connection() as conn:
            existing = await self._fetch_role_by_tuple(conn, base_params)
            if existing is not None:
                return existing

            for hash_len in NAMESPACE_ACL_ROLE_HASH_LENGTHS:
                role_names = build_namespace_acl_role_names(
                    tenant_name,
                    normalized_namespace,
                    normalized_access,
                    hash_len=hash_len,
                )
                insert_params = {
                    **base_params,
                    "catalog_role_name": role_names.catalog_role_name,
                    "principal_role_name": role_names.principal_role_name,
                    "role_name_hash_len": role_names.role_name_hash_len,
                }
                cur = await conn.execute(_INSERT_ROLE, insert_params)
                row = await cur.fetchone()
                if row is not None:
                    await conn.commit()
                    return _role_record_from_row(row)

                existing = await self._fetch_role_by_tuple(conn, base_params)
                if existing is not None:
                    await conn.commit()
                    return existing

        raise NamespaceAclRoleCollisionError(
            "namespace ACL role-name hash collision exhausted"
        )

    async def get_active_grant(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        username: str,
    ) -> NamespaceAclGrantRecord | None:
        """Return an active grant row, or None."""
        params = {
            "tenant_name": tenant_name,
            "namespace_name": namespace_name_from_parts(namespace_parts),
            "username": username,
        }
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_ACTIVE_GRANT, params)
            row = await cur.fetchone()
        if row is None:
            return None
        return _grant_record_from_row(row)

    async def get_role(self, role_id: str) -> NamespaceAclRoleRecord | None:
        """Return role metadata by id, or None if it no longer exists."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_ROLE_BY_ID, {"role_id": role_id})
            row = await cur.fetchone()
        if row is None:
            return None
        return _role_record_from_row(row)

    async def list_roles_for_tenant(
        self,
        tenant_name: str,
    ) -> list[NamespaceAclRoleRecord]:
        """List namespace ACL role metadata for one tenant."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _LIST_ROLES_FOR_TENANT,
                {"tenant_name": tenant_name},
            )
            rows = await cur.fetchall()
        return [_role_record_from_row(row) for row in rows]

    async def count_active_grants_for_role(self, role_id: str) -> int:
        """Return the number of non-revoked grants attached to a role."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _COUNT_ACTIVE_GRANTS_FOR_ROLE,
                {"role_id": role_id},
            )
            row = await cur.fetchone()
        return int(row[0]) if row is not None else 0

    async def delete_role(self, role_id: str) -> bool:
        """Delete a namespace ACL role row by id. Returns true when a row was removed."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_DELETE_ROLE, {"role_id": role_id})
            await conn.commit()
            return cur.rowcount > 0

    async def delete_roles_for_tenant(self, tenant_name: str) -> int:
        """Delete every namespace ACL role row for a tenant. Returns the row count."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _DELETE_ROLES_FOR_TENANT,
                {"tenant_name": tenant_name},
            )
            await conn.commit()
            return cur.rowcount or 0

    async def purge_tenant_history(self, tenant_name: str) -> dict[str, int]:
        """Delete all namespace ACL DB history for a deleted tenant."""
        params = {"tenant_name": tenant_name}
        async with self._pool.connection() as conn:
            events_cur = await conn.execute(_DELETE_EVENTS_FOR_TENANT, params)
            grants_cur = await conn.execute(_DELETE_GRANTS_FOR_TENANT, params)
            roles_cur = await conn.execute(_DELETE_ROLES_FOR_TENANT, params)
            await conn.commit()
        return {
            "events": events_cur.rowcount or 0,
            "grants": grants_cur.rowcount or 0,
            "roles": roles_cur.rowcount or 0,
        }

    async def create_or_update_grant(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        username: str,
        access_level: str,
        actor: str,
        status: str = GRANT_STATUS_PENDING,
        message: str | None = None,
    ) -> NamespaceAclGrantMutation:
        """Create a grant, or update the current active grant for a user."""
        normalized_access = normalize_access_level(access_level)
        normalized_status = normalize_grant_status(status)
        normalized_namespace = normalize_namespace_parts(namespace_parts)
        namespace_name = namespace_name_from_parts(normalized_namespace)
        role = await self.ensure_role(
            tenant_name=tenant_name,
            namespace_parts=normalized_namespace,
            access_level=normalized_access,
        )
        params = {
            "role_id": role.id,
            "tenant_name": tenant_name,
            "catalog_name": role.catalog_name,
            "namespace_name": namespace_name,
            "namespace_parts": list(normalized_namespace),
            "username": username,
            "access_level": normalized_access,
            "status": normalized_status,
            "actor": actor,
        }

        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _SELECT_ACTIVE_GRANT_FOR_UPDATE,
                {
                    "tenant_name": tenant_name,
                    "namespace_name": namespace_name,
                    "username": username,
                },
            )
            existing_row = await cur.fetchone()
            existing = (
                _grant_record_from_row(existing_row)
                if existing_row is not None
                else None
            )

            if existing is None:
                cur = await conn.execute(_INSERT_GRANT, params)
                row = await cur.fetchone()
                grant = _grant_record_from_row(row)
                event_type = _create_event_type(normalized_status)
                await self._append_event_on_connection(
                    conn=conn,
                    grant=grant,
                    event_type=event_type,
                    actor=actor,
                    message=message,
                )
                await conn.commit()
                return NamespaceAclGrantMutation(
                    grant=grant,
                    created=True,
                    event_type=event_type,
                )

            if (
                existing.role_id == role.id
                and existing.access_level == normalized_access
                and existing.status == normalized_status
            ):
                event_type = EVENT_GRANT_IDEMPOTENT
                await self._append_event_on_connection(
                    conn=conn,
                    grant=existing,
                    event_type=event_type,
                    actor=actor,
                    old_access_level=existing.access_level,
                    new_access_level=existing.access_level,
                    old_status=existing.status,
                    new_status=existing.status,
                    message=message,
                )
                await conn.commit()
                return NamespaceAclGrantMutation(
                    grant=existing,
                    created=False,
                    event_type=event_type,
                    previous_access_level=existing.access_level,
                    previous_status=existing.status,
                )

            cur = await conn.execute(_UPDATE_GRANT, {**params, "grant_id": existing.id})
            row = await cur.fetchone()
            grant = _grant_record_from_row(row)
            event_type = _update_event_type(
                old_access_level=existing.access_level,
                old_status=existing.status,
                new_access_level=grant.access_level,
                new_status=grant.status,
            )
            await self._append_event_on_connection(
                conn=conn,
                grant=grant,
                event_type=event_type,
                actor=actor,
                old_access_level=existing.access_level,
                new_access_level=grant.access_level,
                old_status=existing.status,
                new_status=grant.status,
                message=message,
            )
            await conn.commit()
            return NamespaceAclGrantMutation(
                grant=grant,
                created=False,
                event_type=event_type,
                previous_access_level=existing.access_level,
                previous_status=existing.status,
            )

    async def revoke_grant(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        username: str,
        actor: str,
        message: str | None = None,
    ) -> NamespaceAclGrantRecord | None:
        """Mark the current active grant revoked and append an audit event."""
        namespace_name = namespace_name_from_parts(namespace_parts)
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _SELECT_ACTIVE_GRANT_FOR_UPDATE,
                {
                    "tenant_name": tenant_name,
                    "namespace_name": namespace_name,
                    "username": username,
                },
            )
            existing_row = await cur.fetchone()
            if existing_row is None:
                return None

            existing = _grant_record_from_row(existing_row)
            cur = await conn.execute(
                _REVOKE_GRANT,
                {
                    "grant_id": existing.id,
                    "actor": actor,
                },
            )
            row = await cur.fetchone()
            grant = _grant_record_from_row(row)
            await self._append_event_on_connection(
                conn=conn,
                grant=grant,
                event_type=EVENT_GRANT_REVOKED,
                actor=actor,
                old_access_level=existing.access_level,
                new_access_level=grant.access_level,
                old_status=existing.status,
                new_status=grant.status,
                message=message,
            )
            await conn.commit()
            return grant

    async def list_grants_for_tenant(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str] | None = None,
    ) -> list[NamespaceAclGrantRecord]:
        """List grants recorded for one tenant, optionally scoped to a namespace."""
        params = {
            "tenant_name": tenant_name,
            "namespace_name": (
                namespace_name_from_parts(namespace_parts)
                if namespace_parts is not None
                else None
            ),
        }
        async with self._pool.connection() as conn:
            cur = await conn.execute(_LIST_GRANTS_FOR_TENANT, params)
            rows = await cur.fetchall()
        return [_grant_record_from_row(row) for row in rows]

    async def list_active_grants_for_user(
        self,
        username: str,
        statuses: Sequence[str] = (
            GRANT_STATUS_PENDING,
            GRANT_STATUS_ACTIVE,
            GRANT_STATUS_SYNC_ERROR,
        ),
    ) -> list[NamespaceAclGrantRecord]:
        """List non-revoked grants for a user that should be reconciled."""
        normalized_statuses = [normalize_grant_status(status) for status in statuses]
        params = {
            "username": username,
            "statuses": normalized_statuses,
        }
        async with self._pool.connection() as conn:
            cur = await conn.execute(_LIST_ACTIVE_GRANTS_FOR_USER, params)
            rows = await cur.fetchall()
        return [_grant_record_from_row(row) for row in rows]

    async def list_usernames_for_sync(
        self,
        tenant_name: str | None = None,
        statuses: Sequence[str] = (
            GRANT_STATUS_PENDING,
            GRANT_STATUS_ACTIVE,
            GRANT_STATUS_SHADOWED,
            GRANT_STATUS_SYNC_ERROR,
        ),
    ) -> list[str]:
        """List users with non-revoked namespace ACL state that can be reconciled."""
        normalized_statuses = [normalize_grant_status(status) for status in statuses]
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _LIST_USERNAMES_FOR_SYNC,
                {
                    "tenant_name": tenant_name,
                    "statuses": normalized_statuses,
                },
            )
            rows = await cur.fetchall()
        return [str(row[0]) for row in rows]

    async def update_grant_status(
        self,
        grant_id: str,
        status: str,
        actor: str = "system",
        last_synced_at: datetime | None = None,
        last_sync_error: str | None = None,
        event_type: str | None = None,
        message: str | None = None,
    ) -> NamespaceAclGrantRecord | None:
        """Update a grant status after reconciliation and append an event."""
        normalized_status = normalize_grant_status(status)
        normalized_event_type = (
            normalize_event_type(event_type)
            if event_type is not None
            else _status_event_type(normalized_status)
        )
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _UPDATE_GRANT_STATUS,
                {
                    "grant_id": grant_id,
                    "status": normalized_status,
                    "actor": actor,
                    "last_synced_at": last_synced_at,
                    "last_sync_error": last_sync_error,
                },
            )
            row = await cur.fetchone()
            if row is None:
                return None

            grant = _grant_record_from_row(row)
            await self._append_event_on_connection(
                conn=conn,
                grant=grant,
                event_type=normalized_event_type,
                actor=actor,
                new_access_level=grant.access_level,
                new_status=grant.status,
                message=message,
            )
            await conn.commit()
            return grant

    async def append_event(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        event_type: str,
        actor: str,
        username: str | None = None,
        grant_id: str | None = None,
        old_access_level: str | None = None,
        new_access_level: str | None = None,
        old_status: str | None = None,
        new_status: str | None = None,
        message: str | None = None,
    ) -> None:
        """Append an audit event, including validation failures without a grant row."""
        normalized_event_type = normalize_event_type(event_type)
        namespace_name = namespace_name_from_parts(namespace_parts)
        params = {
            "grant_id": grant_id,
            "tenant_name": tenant_name,
            "namespace_name": namespace_name,
            "username": username,
            "event_type": normalized_event_type,
            "old_access_level": old_access_level,
            "new_access_level": new_access_level,
            "old_status": old_status,
            "new_status": new_status,
            "actor": actor,
            "message": message,
        }
        async with self._pool.connection() as conn:
            await conn.execute(_INSERT_EVENT, params)
            await conn.commit()

    async def _fetch_role_by_tuple(
        self,
        conn: Any,
        params: dict[str, Any],
    ) -> NamespaceAclRoleRecord | None:
        cur = await conn.execute(_SELECT_ROLE_BY_TUPLE, params)
        row = await cur.fetchone()
        if row is None:
            return None
        return _role_record_from_row(row)

    async def _append_event_on_connection(
        self,
        conn: Any,
        grant: NamespaceAclGrantRecord,
        event_type: EventType,
        actor: str,
        old_access_level: AccessLevel | None = None,
        new_access_level: AccessLevel | None = None,
        old_status: GrantStatus | None = None,
        new_status: GrantStatus | None = None,
        message: str | None = None,
    ) -> None:
        params = {
            "grant_id": grant.id,
            "tenant_name": grant.tenant_name,
            "namespace_name": grant.namespace_name,
            "username": grant.username,
            "event_type": event_type,
            "old_access_level": old_access_level,
            "new_access_level": new_access_level,
            "old_status": old_status,
            "new_status": new_status,
            "actor": actor,
            "message": message,
        }
        await conn.execute(_INSERT_EVENT, params)


def _role_record_from_row(row: Sequence[Any]) -> NamespaceAclRoleRecord:
    return NamespaceAclRoleRecord(
        id=str(row[0]),
        tenant_name=row[1],
        catalog_name=row[2],
        namespace_name=row[3],
        namespace_parts=tuple(row[4]),
        access_level=row[5],
        catalog_role_name=row[6],
        principal_role_name=row[7],
        role_name_hash_len=row[8],
        created_at=row[9],
        updated_at=row[10],
    )


def _grant_record_from_row(row: Sequence[Any]) -> NamespaceAclGrantRecord:
    return NamespaceAclGrantRecord(
        id=str(row[0]),
        role_id=str(row[1]),
        tenant_name=row[2],
        catalog_name=row[3],
        namespace_name=row[4],
        namespace_parts=tuple(row[5]),
        username=row[6],
        access_level=row[7],
        status=row[8],
        granted_by=row[9],
        granted_at=row[10],
        updated_by=row[11],
        updated_at=row[12],
        revoked_by=row[13],
        revoked_at=row[14],
        last_synced_at=row[15],
        last_sync_error=row[16],
    )


def _create_event_type(status: GrantStatus) -> EventType:
    if status == GRANT_STATUS_SHADOWED:
        return EVENT_GRANT_SHADOWED
    return EVENT_GRANT_CREATED


def _update_event_type(
    old_access_level: AccessLevel,
    old_status: GrantStatus,
    new_access_level: AccessLevel,
    new_status: GrantStatus,
) -> EventType:
    if old_access_level != new_access_level:
        return EVENT_ACCESS_LEVEL_CHANGED
    if new_status == GRANT_STATUS_SHADOWED and old_status != GRANT_STATUS_SHADOWED:
        return EVENT_GRANT_SHADOWED
    if new_status == GRANT_STATUS_ACTIVE and old_status != GRANT_STATUS_ACTIVE:
        return EVENT_GRANT_ACTIVATED
    return EVENT_GRANT_IDEMPOTENT


def _status_event_type(status: GrantStatus) -> EventType:
    if status == GRANT_STATUS_ACTIVE:
        return EVENT_SYNC_HEALED
    if status == GRANT_STATUS_SYNC_ERROR:
        return EVENT_SYNC_FAILED
    if status == GRANT_STATUS_SHADOWED:
        return EVENT_GRANT_SHADOWED
    return EVENT_GRANT_IDEMPOTENT
