"""PostgreSQL repository for tenant_metadata and tenant_stewards tables."""

import logging
from datetime import datetime, timezone

from psycopg_pool import AsyncConnectionPool

from service.cache import SingleFlightTTLCache

logger = logging.getLogger(__name__)

# Per-replica TTL for read-side metadata caches. Aligned with the
# GroupManager caches so the whole list_tenants path collapses to
# ~zero work on a hot pod between mutations. Mutations explicitly
# invalidate the affected keys for in-pod read-after-write.
_METADATA_CACHE_TTL_SECONDS = 60.0

# Sentinel key for "all metadata"; list_metadata() takes no args.
_LIST_METADATA_CACHE_KEY = "__all__"

# ── tenant_metadata queries ──────────────────────────────────────────────────

_INSERT_METADATA = """
INSERT INTO tenant_metadata (tenant_name, display_name, description, website,
                             organization, created_by, created_at, updated_at)
VALUES (%(tenant_name)s, %(display_name)s, %(description)s, %(website)s,
        %(organization)s, %(created_by)s, %(created_at)s, %(updated_at)s)
ON CONFLICT (tenant_name) DO NOTHING
RETURNING tenant_name, display_name, description, website, organization,
         created_by, created_at, updated_at, updated_by;
"""

_SELECT_METADATA = """
SELECT tenant_name, display_name, description, website, organization,
       created_by, created_at, updated_at, updated_by
  FROM tenant_metadata
 WHERE tenant_name = %(tenant_name)s;
"""

_SELECT_ALL_METADATA = """
SELECT tenant_name, display_name, description, website, organization,
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
    "website",
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
    """Async PostgreSQL store for tenant metadata and steward assignments.

    Reads are served from per-process TTL caches (one per logical query)
    with single-flight protection. Mutations invalidate the affected
    keys immediately so an operator who just ran ``add_steward`` sees
    the new state on the next read in the same pod regardless of TTL.
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

        # ── Read-side caches ──
        # Each cache is keyed by the natural identity of the query.
        # Caches are intentionally per-instance (so pytest gives every
        # test a fresh cache) and per-process (so each MMS replica
        # maintains its own — cross-replica sharing is a future
        # optimization).
        self._list_metadata_cache: SingleFlightTTLCache[list[dict]] = (
            SingleFlightTTLCache(
                name="list_metadata",
                maxsize=1,
                ttl_seconds=_METADATA_CACHE_TTL_SECONDS,
            )
        )
        self._metadata_cache: SingleFlightTTLCache[dict | None] = SingleFlightTTLCache(
            name="metadata",
            maxsize=1024,
            ttl_seconds=_METADATA_CACHE_TTL_SECONDS,
        )
        self._stewards_cache: SingleFlightTTLCache[list[dict]] = SingleFlightTTLCache(
            name="stewards",
            maxsize=1024,
            ttl_seconds=_METADATA_CACHE_TTL_SECONDS,
        )
        self._steward_tenants_cache: SingleFlightTTLCache[list[str]] = (
            SingleFlightTTLCache(
                name="steward_tenants",
                maxsize=4096,
                ttl_seconds=_METADATA_CACHE_TTL_SECONDS,
            )
        )
        self._is_steward_cache: SingleFlightTTLCache[bool] = SingleFlightTTLCache(
            name="is_steward",
            maxsize=8192,
            ttl_seconds=_METADATA_CACHE_TTL_SECONDS,
        )

    # ── Cache invalidation helpers ───────────────────────────────────────

    def _invalidate_metadata(self, tenant_name: str) -> None:
        """Bust caches affected by metadata create/update/delete for a tenant.

        ``list_metadata`` is also dropped because it includes this tenant.
        """
        self._metadata_cache.invalidate(tenant_name)
        self._list_metadata_cache.invalidate(_LIST_METADATA_CACHE_KEY)

    def _invalidate_stewardship(self, tenant_name: str, username: str) -> None:
        """Bust caches affected by add/remove_steward(tenant, user)."""
        self._stewards_cache.invalidate(tenant_name)
        self._steward_tenants_cache.invalidate(username)
        self._is_steward_cache.invalidate((tenant_name, username))

    def _invalidate_all_stewardship(self) -> None:
        """Bust ALL stewardship caches (used on delete_metadata cascade).

        delete_metadata cascades to tenant_stewards via FK. We don't
        know which users had stewardship rows for the deleted tenant
        without an extra query, so we drop the per-user / per-(tenant,
        user) caches wholesale. This is rare (only on tenant deletion)
        and keeps the invariant simple.
        """
        self._stewards_cache.invalidate_all()
        self._steward_tenants_cache.invalidate_all()
        self._is_steward_cache.invalidate_all()

    # ── tenant_metadata ──────────────────────────────────────────────────

    async def create_metadata(
        self,
        tenant_name: str,
        created_by: str,
        *,
        display_name: str | None = None,
        description: str | None = None,
        website: str | None = None,
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
                    "website": website,
                    "organization": organization,
                    "created_by": created_by,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            row = await cur.fetchone()
            await conn.commit()
        # Invalidate even on the conflict (None) path: a concurrent
        # writer may have just inserted and we want subsequent reads
        # to refetch rather than return our stale cached miss.
        self._invalidate_metadata(tenant_name)
        if row is None:
            return None
        return _row_to_metadata(row)

    async def get_metadata(self, tenant_name: str) -> dict | None:
        """Return metadata for a single tenant, or None if not found."""

        async def _load() -> dict | None:
            async with self._pool.connection() as conn:
                cur = await conn.execute(_SELECT_METADATA, {"tenant_name": tenant_name})
                row = await cur.fetchone()
            if row is None:
                return None
            return _row_to_metadata(row)

        return await self._metadata_cache.get_or_load(tenant_name, _load)

    async def update_metadata(
        self,
        tenant_name: str,
        updated_by: str,
        *,
        display_name: str | None = None,
        description: str | None = None,
        website: str | None = None,
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
        if website is not None:
            sets.append("website = %(website)s")
            params["website"] = website
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
        # Bust before returning so any in-flight reader behind us
        # picks up the new value rather than our pre-update cached row.
        self._invalidate_metadata(tenant_name)
        if row is None:
            return None
        return _row_to_metadata(row)

    async def delete_metadata(self, tenant_name: str) -> bool:
        """Delete tenant metadata (cascades to tenant_stewards). Returns True if deleted."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_DELETE_METADATA, {"tenant_name": tenant_name})
            await conn.commit()
        deleted = cur.rowcount > 0
        if deleted:
            # Metadata row gone; cascade also drops every steward row
            # for this tenant, so we wipe ALL stewardship caches (we
            # don't know which usernames were affected without an
            # extra query). delete_metadata is rare, so the wholesale
            # invalidation is acceptable.
            self._invalidate_metadata(tenant_name)
            self._invalidate_all_stewardship()
        return deleted

    async def list_metadata(self) -> list[dict]:
        """Return metadata for all tenants."""

        async def _load() -> list[dict]:
            async with self._pool.connection() as conn:
                cur = await conn.execute(_SELECT_ALL_METADATA)
                rows = await cur.fetchall()
            return [_row_to_metadata(row) for row in rows]

        return await self._list_metadata_cache.get_or_load(
            _LIST_METADATA_CACHE_KEY, _load
        )

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
        # Membership of (tenant -> stewards) and (user -> tenants) just
        # changed; bust both per-key caches plus the (tenant, user)
        # is_steward entry.
        self._invalidate_stewardship(tenant_name, username)
        return _row_to_steward(row)

    async def remove_steward(self, tenant_name: str, username: str) -> bool:
        """Remove a steward assignment. Returns True if removed."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _DELETE_STEWARD,
                {"tenant_name": tenant_name, "username": username},
            )
            await conn.commit()
        removed = cur.rowcount > 0
        # Invalidate even on the "not removed" path (the cached entries
        # may already be stale relative to a concurrent writer).
        self._invalidate_stewardship(tenant_name, username)
        return removed

    async def get_stewards(self, tenant_name: str) -> list[dict]:
        """Return all stewards for a tenant."""

        async def _load() -> list[dict]:
            async with self._pool.connection() as conn:
                cur = await conn.execute(_SELECT_STEWARDS, {"tenant_name": tenant_name})
                rows = await cur.fetchall()
            return [_row_to_steward(row) for row in rows]

        return await self._stewards_cache.get_or_load(tenant_name, _load)

    async def is_steward(self, tenant_name: str, username: str) -> bool:
        """Check if a user is a steward for the given tenant."""

        async def _load() -> bool:
            async with self._pool.connection() as conn:
                cur = await conn.execute(
                    _IS_STEWARD,
                    {"tenant_name": tenant_name, "username": username},
                )
                return await cur.fetchone() is not None

        return await self._is_steward_cache.get_or_load((tenant_name, username), _load)

    async def get_steward_tenants(self, username: str) -> list[str]:
        """Return tenant names where the user is a steward."""

        async def _load() -> list[str]:
            async with self._pool.connection() as conn:
                cur = await conn.execute(
                    _SELECT_STEWARD_TENANTS, {"username": username}
                )
                rows = await cur.fetchall()
            return [row[0] for row in rows]

        return await self._steward_tenants_cache.get_or_load(username, _load)
