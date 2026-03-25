"""PostgreSQL repository for tenant_metadata and tenant_stewards tables."""

import logging
from datetime import datetime, timezone

from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

# ── tenant_metadata queries ──────────────────────────────────────────────────

_INSERT_METADATA = """
INSERT INTO tenant_metadata (tenant_name, display_name, description, organization,
                             created_by, created_at, updated_at)
VALUES (%(tenant_name)s, %(display_name)s, %(description)s, %(organization)s,
        %(created_by)s, %(created_at)s, %(updated_at)s)
ON CONFLICT (tenant_name) DO NOTHING
RETURNING *;
"""

_SELECT_METADATA = """
SELECT tenant_name, display_name, description, organization,
       created_by, created_at, updated_at, updated_by
  FROM tenant_metadata
 WHERE tenant_name = %(tenant_name)s;
"""

_SELECT_ALL_METADATA = """
SELECT tenant_name, display_name, description, organization,
       created_by, created_at, updated_at, updated_by
  FROM tenant_metadata;
"""

_DELETE_METADATA = """
DELETE FROM tenant_metadata WHERE tenant_name = %(tenant_name)s;
"""

# ── tenant_stewards queries ──────────────────────────────────────────────────

_UPSERT_STEWARD = """
INSERT INTO tenant_stewards (tenant_name, username, assigned_by, assigned_at)
VALUES (%(tenant_name)s, %(username)s, %(assigned_by)s, %(assigned_at)s)
ON CONFLICT (tenant_name, username) DO UPDATE SET tenant_name = tenant_stewards.tenant_name
RETURNING tenant_name, username, assigned_by, assigned_at;
"""

_DELETE_STEWARD = """
DELETE FROM tenant_stewards
 WHERE tenant_name = %(tenant_name)s AND username = %(username)s;
"""

_SELECT_STEWARDS = """
SELECT tenant_name, username, assigned_by, assigned_at
  FROM tenant_stewards
 WHERE tenant_name = %(tenant_name)s;
"""

_IS_STEWARD = """
SELECT 1 FROM tenant_stewards
 WHERE tenant_name = %(tenant_name)s AND username = %(username)s;
"""

_SELECT_STEWARD_TENANTS = """
SELECT tenant_name FROM tenant_stewards WHERE username = %(username)s;
"""

_METADATA_COLUMNS = (
    "tenant_name",
    "display_name",
    "description",
    "organization",
    "created_by",
    "created_at",
    "updated_at",
    "updated_by",
)

_STEWARD_COLUMNS = ("tenant_name", "username", "assigned_by", "assigned_at")


def _row_to_metadata(row: tuple) -> dict:
    return dict(zip(_METADATA_COLUMNS, row))


def _row_to_steward(row: tuple) -> dict:
    return dict(zip(_STEWARD_COLUMNS, row))


class TenantMetadataStore:
    """Async PostgreSQL store for tenant metadata and steward assignments."""

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

    # ── tenant_metadata ──────────────────────────────────────────────────

    async def create_metadata(
        self,
        tenant_name: str,
        created_by: str,
        *,
        display_name: str | None = None,
        description: str | None = None,
        organization: str | None = None,
    ) -> dict | None:
        """Create a tenant_metadata row. Returns None if already exists (idempotent)."""
        now = datetime.now(timezone.utc)
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _INSERT_METADATA,
                {
                    "tenant_name": tenant_name,
                    "display_name": display_name or tenant_name,
                    "description": description,
                    "organization": organization,
                    "created_by": created_by,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            row = await cur.fetchone()
            await conn.commit()
        if row is None:
            return None
        return _row_to_metadata(row)

    async def get_metadata(self, tenant_name: str) -> dict | None:
        """Return metadata for a single tenant, or None if not found."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_METADATA, {"tenant_name": tenant_name})
            row = await cur.fetchone()
        if row is None:
            return None
        return _row_to_metadata(row)

    async def update_metadata(
        self,
        tenant_name: str,
        updated_by: str,
        *,
        display_name: str | None = None,
        description: str | None = None,
        organization: str | None = None,
    ) -> dict | None:
        """Partial update of tenant metadata. Only non-None fields are set."""
        sets: list[str] = ["updated_at = %(updated_at)s", "updated_by = %(updated_by)s"]
        params: dict = {
            "tenant_name": tenant_name,
            "updated_at": datetime.now(timezone.utc),
            "updated_by": updated_by,
        }
        if display_name is not None:
            sets.append("display_name = %(display_name)s")
            params["display_name"] = display_name
        if description is not None:
            sets.append("description = %(description)s")
            params["description"] = description
        if organization is not None:
            sets.append("organization = %(organization)s")
            params["organization"] = organization

        sql = (
            f"UPDATE tenant_metadata SET {', '.join(sets)} "
            f"WHERE tenant_name = %(tenant_name)s "
            f"RETURNING {', '.join(_METADATA_COLUMNS)};"
        )
        async with self._pool.connection() as conn:
            cur = await conn.execute(sql, params)
            row = await cur.fetchone()
            await conn.commit()
        if row is None:
            return None
        return _row_to_metadata(row)

    async def delete_metadata(self, tenant_name: str) -> bool:
        """Delete tenant metadata (cascades to tenant_stewards). Returns True if deleted."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_DELETE_METADATA, {"tenant_name": tenant_name})
            await conn.commit()
        return cur.rowcount > 0

    async def list_metadata(self) -> list[dict]:
        """Return metadata for all tenants."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_ALL_METADATA)
            rows = await cur.fetchall()
        return [_row_to_metadata(row) for row in rows]

    # ── tenant_stewards ──────────────────────────────────────────────────

    async def add_steward(
        self, tenant_name: str, username: str, assigned_by: str
    ) -> dict:
        """Assign a user as steward (idempotent). Always returns the steward row."""
        now = datetime.now(timezone.utc)
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _UPSERT_STEWARD,
                {
                    "tenant_name": tenant_name,
                    "username": username,
                    "assigned_by": assigned_by,
                    "assigned_at": now,
                },
            )
            row = await cur.fetchone()
            await conn.commit()
        return _row_to_steward(row)

    async def remove_steward(self, tenant_name: str, username: str) -> bool:
        """Remove a steward assignment. Returns True if removed."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _DELETE_STEWARD,
                {"tenant_name": tenant_name, "username": username},
            )
            await conn.commit()
        return cur.rowcount > 0

    async def get_stewards(self, tenant_name: str) -> list[dict]:
        """Return all stewards for a tenant."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_STEWARDS, {"tenant_name": tenant_name})
            rows = await cur.fetchall()
        return [_row_to_steward(row) for row in rows]

    async def is_steward(self, tenant_name: str, username: str) -> bool:
        """Check if a user is a steward for the given tenant."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _IS_STEWARD,
                {"tenant_name": tenant_name, "username": username},
            )
            return await cur.fetchone() is not None

    async def get_steward_tenants(self, username: str) -> list[str]:
        """Return tenant names where the user is a steward."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_STEWARD_TENANTS, {"username": username})
            rows = await cur.fetchall()
        return [row[0] for row in rows]
