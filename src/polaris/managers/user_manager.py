"""High-level Polaris user-lifecycle orchestration.

Mirrors the public shape of :class:`MinioUserManager` so that route handlers
can call ``minio_user_manager.create_user(...)`` followed by
``polaris_user_manager.create_user(...)`` and have both backends end up in
matching states. Each call here is a thin orchestration over
:class:`PolarisService`; all underlying Polaris operations are idempotent
(409 → fetch existing, 404 → success on delete) so retrying after a partial
failure is safe.
"""

import logging

from polaris.constants import (
    PERSONAL_CATALOG_ADMIN_ROLE,
    ICEBERG_STORAGE_SUBDIRECTORY,
    personal_catalog_name,
    personal_principal_role,
)
from polaris.polaris_service import PolarisService

logger = logging.getLogger(__name__)


class PolarisUserManager:
    """User-lifecycle orchestration over the Polaris REST API."""

    def __init__(
        self,
        polaris_service: PolarisService,
        users_sql_warehouse_base: str,
    ) -> None:
        """
        Args:
            polaris_service: low-level Polaris REST client.
            users_sql_warehouse_base: ``s3a://bucket/users-sql-warehouse`` —
                the warehouse root under which each user's ``{username}/iceberg/``
                subdirectory becomes the personal catalog's storage location.
        """
        self._polaris = polaris_service
        self._users_sql_warehouse_base = users_sql_warehouse_base

    def _personal_storage_location(self, username: str) -> str:
        return (
            f"{self._users_sql_warehouse_base}/{username}/"
            f"{ICEBERG_STORAGE_SUBDIRECTORY}/"
        )

    async def create_user(self, username: str) -> None:
        """Provision the user's personal Polaris assets.

        Steps (all idempotent — safe to call repeatedly):
          1. Personal catalog ``user_{username}``
          2. Polaris principal ``{username}``
          3. Catalog role ``catalog_admin`` with ``CATALOG_MANAGE_CONTENT``
          4. Principal role ``{username}_role`` bound to the catalog role
          5. Bind the principal role to the principal

        Group-tenant role bindings are NOT done here — call
        :meth:`PolarisGroupManager.add_user_to_group` for each group the user
        belongs to (the route layer handles that orchestration).
        """
        catalog_name = personal_catalog_name(username)
        storage_location = self._personal_storage_location(username)

        # 1. Personal catalog
        await self._polaris.create_catalog(
            name=catalog_name, storage_location=storage_location
        )

        # 2. Principal
        await self._polaris.create_principal(name=username)

        # 3. catalog_admin role on the personal catalog with CATALOG_MANAGE_CONTENT
        await self._polaris.create_catalog_role(
            catalog=catalog_name, role_name=PERSONAL_CATALOG_ADMIN_ROLE
        )
        await self._polaris.grant_catalog_privilege(
            catalog=catalog_name,
            role_name=PERSONAL_CATALOG_ADMIN_ROLE,
            privilege="CATALOG_MANAGE_CONTENT",
        )

        # 4. Principal role bound to the catalog role
        principal_role = personal_principal_role(username)
        await self._polaris.create_principal_role(role_name=principal_role)
        await self._polaris.grant_catalog_role_to_principal_role(
            catalog=catalog_name,
            catalog_role=PERSONAL_CATALOG_ADMIN_ROLE,
            principal_role=principal_role,
        )

        # 5. Bind principal role to principal
        await self._polaris.grant_principal_role_to_principal(
            principal=username, principal_role=principal_role
        )

        logger.info("Provisioned Polaris assets for user %s", username)

    async def delete_user(self, username: str) -> None:
        """Tear down a user's personal Polaris assets in reverse creation order.

        Each step is best-effort and 404-tolerant: a partial failure in one
        step does not block the others. Tenant role bindings (catalog
        memberships from group membership) are cleaned up separately by
        :meth:`PolarisGroupManager.remove_user_from_group` on each group
        before this call.
        """
        principal_role = personal_principal_role(username)
        catalog_name = personal_catalog_name(username)

        # Reverse-create order. Each delete here is already 404-tolerant in
        # PolarisService and re-raises only on non-404 errors; we additionally
        # log+continue here so a single failure doesn't strand later cleanup.
        try:
            await self._polaris.delete_principal_role(principal_role)
        except Exception as e:
            logger.warning(
                "Failed to delete Polaris principal role %s: %s; continuing.",
                principal_role,
                e,
            )

        try:
            await self._polaris.delete_principal(username)
        except Exception as e:
            logger.warning(
                "Failed to delete Polaris principal %s: %s; continuing.",
                username,
                e,
            )

        try:
            await self._polaris.delete_catalog(catalog_name)
        except Exception as e:
            logger.warning(
                "Failed to delete Polaris catalog %s: %s; continuing.",
                catalog_name,
                e,
            )

        logger.info("Deleted Polaris assets for user %s", username)
