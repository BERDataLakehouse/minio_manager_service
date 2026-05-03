"""High-level Polaris group/tenant orchestration.

Mirrors the public shape of :class:`MinioGroupManager` so the route layer can
call ``minio_group_manager.foo(...)`` followed by
``polaris_group_manager.foo(...)`` and have both backends end up in matching
states. Read-only group conventions (``{group}ro``) are normalised here so
callers can pass either the base or RO group name.
"""

import logging

from polaris.constants import (
    ICEBERG_STORAGE_SUBDIRECTORY,
    normalize_group_name_for_polaris,
    tenant_reader_principal_role,
    tenant_writer_principal_role,
)
from polaris.polaris_service import PolarisService

logger = logging.getLogger(__name__)


class PolarisGroupManager:
    """Group/tenant lifecycle orchestration over the Polaris REST API."""

    def __init__(
        self,
        polaris_service: PolarisService,
        tenant_sql_warehouse_base: str,
    ) -> None:
        """
        Args:
            polaris_service: low-level Polaris REST client.
            tenant_sql_warehouse_base: ``s3a://bucket/tenant-sql-warehouse`` —
                the warehouse root under which each tenant's
                ``{group}/iceberg/`` subdirectory becomes the catalog's
                storage location.
        """
        self._polaris = polaris_service
        self._tenant_sql_warehouse_base = tenant_sql_warehouse_base

    def _tenant_storage_location(self, base_group: str) -> str:
        return (
            f"{self._tenant_sql_warehouse_base}/{base_group}/"
            f"{ICEBERG_STORAGE_SUBDIRECTORY}/"
        )

    async def ensure_catalog(self, group_name: str) -> None:
        """Ensure the tenant catalog and writer/reader catalog roles exist.

        Idempotent. Use this when you want to provision the catalog without
        binding any specific user (e.g., a backfill / migration endpoint).
        """
        await self._polaris.ensure_tenant_catalog(
            group_name, self._tenant_storage_location(group_name)
        )

    async def create_group(self, group_name: str, creator: str) -> None:
        """Provision a tenant catalog with writer/reader principal roles.

        Idempotent: PolarisService.ensure_tenant_catalog handles the 409
        "already exists" case for every nested resource.

        Mirrors :class:`MinioGroupManager.create_group` in that it also wires
        the creator into the writer (and reader) principal-role bindings — the
        MinIO side adds the creator to both the base and ``{group}ro`` MinIO
        groups, so this matches.
        """
        await self.ensure_catalog(group_name)
        # Mirror: MinIO put creator in both groups; Polaris does the same so
        # `add_user_to_group` and `create_group` give consistent state.
        await self.add_user_to_group(creator, group_name)
        await self.add_user_to_group(creator, f"{group_name}ro")

        logger.info(
            "Provisioned Polaris tenant catalog and creator bindings for group %s",
            group_name,
        )

    async def delete_group(self, group_name: str) -> None:
        """Drop a tenant catalog and its associated principal roles.

        For input that is the read-only variant (``{group}ro``) this is a
        no-op: the RO variant has no catalog of its own — its bindings live
        under the base catalog, which is dropped when the base group is
        deleted.
        """
        base_group, is_ro = normalize_group_name_for_polaris(group_name)
        if is_ro or not base_group:
            logger.debug(
                "Polaris delete_group skipping read-only/empty input %s "
                "(catalog lives under base group)",
                group_name,
            )
            return
        await self._polaris.drop_tenant_catalog(base_group)
        logger.info("Dropped Polaris tenant catalog for group %s", base_group)

    async def add_user_to_group(self, username: str, group_name: str) -> None:
        """Grant the user the matching writer or reader principal role.

        ``{group}ro`` inputs map to ``{group}ro_member`` (reader) on the base
        catalog; the plain group name maps to ``{group}_member`` (writer).
        Catalog and principal are ensured first so this method works for
        pre-Polaris groups/users that existed before the service was wired in.
        """
        base_group, is_ro = normalize_group_name_for_polaris(group_name)
        if not base_group:
            logger.debug(
                "Polaris add_user_to_group skipping empty base group from %s",
                group_name,
            )
            return

        # Ensure target catalog and principal exist so this method is
        # self-healing for legacy groups/users.
        await self._polaris.ensure_tenant_catalog(
            base_group, self._tenant_storage_location(base_group)
        )
        await self._polaris.create_principal(name=username)

        principal_role = (
            tenant_reader_principal_role(base_group)
            if is_ro
            else tenant_writer_principal_role(base_group)
        )
        await self._polaris.grant_principal_role_to_principal(username, principal_role)

    async def remove_user_from_group(self, username: str, group_name: str) -> None:
        """Revoke the user's writer or reader principal-role binding.

        Idempotent: revoking a binding that was never granted returns 404
        which PolarisService.revoke_principal_role_from_principal swallows.
        """
        base_group, is_ro = normalize_group_name_for_polaris(group_name)
        if not base_group:
            logger.debug(
                "Polaris remove_user_from_group skipping empty base group from %s",
                group_name,
            )
            return

        principal_role = (
            tenant_reader_principal_role(base_group)
            if is_ro
            else tenant_writer_principal_role(base_group)
        )
        await self._polaris.revoke_principal_role_from_principal(
            username, principal_role
        )
