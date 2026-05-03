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
from typing import Any

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

    async def reset_credentials(self, username: str) -> dict[str, Any]:
        """Reset and return Polaris client credentials for the user's principal.

        Mirrors :meth:`MinioUserManager.get_or_rotate_user_credentials` —
        callers (notably :class:`PolarisCredentialService`) use this as the
        credential-issuance step. Assumes the principal already exists; pair
        with :meth:`create_user` (idempotent) for self-bootstrap callers.

        Returns:
            The full Polaris response dict; ``["credentials"]`` carries
            ``clientId`` and ``clientSecret``.
        """
        return await self._polaris.reset_principal_credentials(name=username)

    async def delete_user(self, username: str) -> None:
        """Tear down a user's personal Polaris assets in reverse creation order.

        Each step is best-effort and 404-tolerant — partial failures are
        logged via :meth:`PolarisService.safe_delete` (shared format with
        ``drop_tenant_catalog`` so log aggregators see one prefix) and do not
        block later steps.

        Tenant role bindings (memberships from group membership) are revoked
        first defensively in case the configured Polaris version doesn't
        auto-cascade on ``delete_principal``. Then we delete the personal
        principal role, the principal itself, and the personal catalog.
        """
        catalog_name = personal_catalog_name(username)
        user_principal_role = personal_principal_role(username)

        # 1. Revoke every principal-role binding the user holds before
        # deleting the principal. Polaris versions vary on whether
        # delete_principal cascades to remove its bindings; revoking
        # explicitly first means we never leave orphan bindings pointing
        # at a deleted principal regardless of server behavior. The
        # personal {username}_role binding is included here too — that's
        # fine, the role itself is dropped in step 2.
        try:
            bound_roles = await self._polaris.get_principal_roles_for_principal(
                username
            )
        except Exception as e:
            # If we can't list bindings, fall back to the original
            # delete-and-hope-it-cascades flow rather than aborting the
            # whole teardown.
            logger.warning(
                "Could not list Polaris principal roles for %s: %s; "
                "skipping defensive revoke and proceeding to delete.",
                username,
                e,
            )
            bound_roles = []

        for role in bound_roles:
            await self._polaris.safe_delete(
                f"binding {username} -> {role}",
                self._polaris.revoke_principal_role_from_principal(username, role),
            )

        # 2. Reverse-create order on the personal assets.
        await self._polaris.safe_delete(
            f"principal role {user_principal_role}",
            self._polaris.delete_principal_role(user_principal_role),
        )
        await self._polaris.safe_delete(
            f"principal {username}",
            self._polaris.delete_principal(username),
        )
        await self._polaris.safe_delete(
            f"catalog {catalog_name}",
            self._polaris.delete_catalog(catalog_name),
        )

        logger.info("Deleted Polaris assets for user %s", username)
