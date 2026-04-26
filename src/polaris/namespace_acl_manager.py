"""Reconciliation manager for Polaris namespace ACL grants."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Sequence

from minio.managers.policy_manager import PolicyManager
from polaris.constants import ICEBERG_STORAGE_SUBDIRECTORY
from polaris.namespace_acl_policy import (
    MAX_NAMESPACE_ACL_POLICY_BYTES,
    NamespaceAclPolicyGrant,
    build_namespace_acl_policy,
    compact_policy_size_bytes,
    namespace_acl_policy_name,
)
from polaris.namespace_acl_store import (
    EVENT_GRANT_ACTIVATED,
    EVENT_GRANT_SHADOWED,
    EVENT_SYNC_FAILED,
    EVENT_SYNC_HEALED,
    EVENT_VALIDATION_FAILED,
    GRANT_STATUS_ACTIVE,
    GRANT_STATUS_PENDING,
    GRANT_STATUS_SHADOWED,
    GRANT_STATUS_SYNC_ERROR,
    NamespaceAclGrantRecord,
    NamespaceAclRoleRecord,
    NamespaceAclStore,
    normalize_namespace_parts,
    tenant_catalog_name,
)
from polaris.polaris_service import PolarisService
from s3.core.distributed_lock import DistributedLockManager
from s3.models.s3_config import S3Config

logger = logging.getLogger(__name__)

DEFAULT_MAX_GRANTS_PER_USER = 50
NAMESPACE_ACL_PRINCIPAL_ROLE_PREFIX = "namespace_acl_"
NAMESPACE_ACL_PRINCIPAL_ROLE_SUFFIX = "_member"


class NamespaceAclValidationError(ValueError):
    """Raised when a namespace is not valid for a namespace ACL grant."""


class NamespaceAclNamespaceNotFoundError(NamespaceAclValidationError):
    """Raised when the target namespace does not exist."""


@dataclass(frozen=True)
class NamespaceAclGrantSyncFailure:
    """Grant-level reconciliation failure."""

    grant_id: str
    username: str
    message: str


@dataclass(frozen=True)
class NamespaceAclUserSyncResult:
    """Result of reconciling namespace ACL side effects for one user."""

    username: str
    policy_name: str
    synced_grants: tuple[str, ...]
    failed_grants: tuple[NamespaceAclGrantSyncFailure, ...]
    revoked_stale_roles: tuple[str, ...]
    policy_size_bytes: int

    @property
    def success(self) -> bool:
        """Return true when no grant failed reconciliation."""
        return not self.failed_grants


@dataclass(frozen=True)
class NamespaceAclGrantOperationResult:
    """Result of grant or revoke intent plus user reconciliation."""

    grant: NamespaceAclGrantRecord | None
    created: bool
    sync_result: NamespaceAclUserSyncResult


@dataclass(frozen=True)
class NamespaceAclCascadeResult:
    """Result of a lifecycle cascade over namespace ACL state."""

    revoked_grants: int
    reconciled_users: tuple[str, ...]
    deleted_principal_roles: tuple[str, ...]


class NamespaceAclManager:
    """Coordinates DB intent with Polaris roles and a consolidated MinIO policy."""

    def __init__(
        self,
        store: NamespaceAclStore,
        polaris_service: PolarisService,
        policy_manager: PolicyManager,
        lock_manager: DistributedLockManager,
        minio_config: S3Config,
        max_grants_per_user: int = DEFAULT_MAX_GRANTS_PER_USER,
        max_policy_bytes: int = MAX_NAMESPACE_ACL_POLICY_BYTES,
    ) -> None:
        self._store = store
        self._polaris_service = polaris_service
        self._policy_manager = policy_manager
        self._lock_manager = lock_manager
        self._minio_config = minio_config
        self._max_grants_per_user = max_grants_per_user
        self._max_policy_bytes = max_policy_bytes

    async def reconcile_user(self, username: str) -> NamespaceAclUserSyncResult:
        """Rebuild Polaris principal roles and the MinIO namespace ACL policy."""
        policy_name = namespace_acl_policy_name(username)
        async with self._lock_manager.namespace_acl_lock(username):
            grants = await self._store.list_active_grants_for_user(username)
            if len(grants) > self._max_grants_per_user:
                return await self._fail_all_grants(
                    username=username,
                    grants=grants,
                    policy_name=policy_name,
                    message=(
                        "namespace ACL grant count exceeds configured "
                        f"limit of {self._max_grants_per_user}"
                    ),
                )

            if grants:
                try:
                    await self._polaris_service.create_principal(username)
                except Exception as e:
                    return await self._fail_all_grants(
                        username=username,
                        grants=grants,
                        policy_name=policy_name,
                        message=f"failed to provision Polaris principal: {e}",
                    )

            synced_grant_ids: list[str] = []
            failures: list[NamespaceAclGrantSyncFailure] = []
            policy_grants: list[NamespaceAclPolicyGrant] = []
            candidate_grants: list[NamespaceAclGrantRecord] = []
            expected_principal_roles: set[str] = set()

            for grant in grants:
                role = await self._store.get_role(grant.role_id)
                if role is None:
                    failure = await self._mark_grant_failed(
                        grant,
                        "namespace ACL role metadata is missing",
                    )
                    failures.append(failure)
                    continue

                try:
                    await self.validate_namespace_for_grant(
                        grant.tenant_name,
                        grant.namespace_parts,
                    )
                    await self._ensure_polaris_assignment(username, grant, role)
                except Exception as e:
                    failure = await self._mark_grant_failed(grant, str(e))
                    failures.append(failure)
                    continue

                expected_principal_roles.add(role.principal_role_name)
                candidate_grants.append(grant)
                policy_grants.append(
                    NamespaceAclPolicyGrant(
                        tenant_name=grant.tenant_name,
                        namespace_parts=grant.namespace_parts,
                        access_level=grant.access_level,
                    )
                )
                synced_grant_ids.append(grant.id)

            policy_size_bytes = 0
            if policy_grants:
                policy = build_namespace_acl_policy(
                    username,
                    policy_grants,
                    self._minio_config,
                )
                policy_size_bytes = compact_policy_size_bytes(policy)
                if policy_size_bytes > self._max_policy_bytes:
                    failures.extend(
                        await self._mark_policy_size_failures(
                            candidate_grants,
                            policy_size_bytes,
                        )
                    )
                    synced_grant_ids = []
                    expected_principal_roles.clear()
                    await self._policy_manager.detach_and_delete_user_policy(
                        policy_name,
                        username,
                    )
                else:
                    await self._policy_manager.upsert_attached_user_policy(
                        policy,
                        username,
                    )
                    await self._mark_grants_active(synced_grant_ids)
            else:
                await self._policy_manager.detach_and_delete_user_policy(
                    policy_name,
                    username,
                )

            revoked_stale_roles = await self._revoke_stale_namespace_roles(
                username,
                expected_principal_roles,
            )

        return NamespaceAclUserSyncResult(
            username=username,
            policy_name=policy_name,
            synced_grants=tuple(synced_grant_ids),
            failed_grants=tuple(failures),
            revoked_stale_roles=tuple(revoked_stale_roles),
            policy_size_bytes=policy_size_bytes,
        )

    async def grant_namespace_access(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        username: str,
        access_level: str,
        actor: str,
        shadowed: bool = False,
    ) -> NamespaceAclGrantOperationResult:
        """Record a namespace ACL grant and reconcile external side effects."""
        try:
            await self.validate_namespace_for_grant(tenant_name, namespace_parts)
        except NamespaceAclValidationError as e:
            await self.record_validation_failure(
                tenant_name=tenant_name,
                namespace_parts=namespace_parts,
                username=username,
                actor=actor,
                message=str(e),
            )
            raise

        await self._polaris_service.create_principal(username)
        status = GRANT_STATUS_SHADOWED if shadowed else GRANT_STATUS_PENDING
        mutation = await self._store.create_or_update_grant(
            tenant_name=tenant_name,
            namespace_parts=namespace_parts,
            username=username,
            access_level=access_level,
            actor=actor,
            status=status,
        )
        sync_result = await self.reconcile_user(username)
        grant = await self._store.get_active_grant(
            tenant_name,
            namespace_parts,
            username,
        )
        return NamespaceAclGrantOperationResult(
            grant=grant or mutation.grant,
            created=mutation.created,
            sync_result=sync_result,
        )

    async def revoke_namespace_access(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        username: str,
        actor: str,
    ) -> NamespaceAclGrantOperationResult | None:
        """Mark a namespace ACL grant revoked and reconcile external side effects."""
        grant = await self._store.revoke_grant(
            tenant_name=tenant_name,
            namespace_parts=namespace_parts,
            username=username,
            actor=actor,
        )
        if grant is None:
            return None
        sync_result = await self.reconcile_user(username)
        return NamespaceAclGrantOperationResult(
            grant=grant,
            created=False,
            sync_result=sync_result,
        )

    async def list_grants_for_tenant(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str] | None = None,
    ) -> list[NamespaceAclGrantRecord]:
        """List grants recorded for one tenant."""
        return await self._store.list_grants_for_tenant(tenant_name, namespace_parts)

    async def list_grants_for_user(
        self,
        username: str,
    ) -> list[NamespaceAclGrantRecord]:
        """List active grants visible to a recipient."""
        return await self._store.list_active_grants_for_user(
            username,
            statuses=(
                GRANT_STATUS_PENDING,
                GRANT_STATUS_ACTIVE,
                GRANT_STATUS_SHADOWED,
                GRANT_STATUS_SYNC_ERROR,
            ),
        )

    async def validate_namespace_for_grant(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
    ) -> None:
        """Validate a namespace exists, is a leaf, and owns its table locations."""
        namespace = normalize_namespace_parts(namespace_parts)
        namespace_name = ".".join(namespace)
        catalog_name = tenant_catalog_name(tenant_name)
        if not await self._polaris_service.namespace_exists(catalog_name, namespace):
            raise NamespaceAclNamespaceNotFoundError(
                f"Namespace '{namespace_name}' not found in tenant '{tenant_name}'"
            )

        child_namespaces = await self._polaris_service.list_namespaces(
            catalog_name,
            parent=namespace,
        )
        if child_namespaces:
            raise NamespaceAclValidationError(
                f"Namespace '{namespace_name}' has child namespaces and cannot be shared as a leaf namespace"
            )

        allowed_prefixes = self._allowed_namespace_location_prefixes(
            tenant_name,
            namespace,
        )
        for table_name in await self._polaris_service.list_tables_in_namespace(
            catalog_name,
            namespace,
        ):
            table = await self._polaris_service.load_table(
                catalog_name,
                namespace,
                table_name,
            )
            locations = _table_locations(table)
            if not locations:
                raise NamespaceAclValidationError(
                    f"Table '{namespace_name}.{table_name}' does not expose a storage location"
                )
            invalid_locations = [
                location
                for location in locations
                if not location.startswith(allowed_prefixes)
            ]
            if invalid_locations:
                raise NamespaceAclValidationError(
                    f"Table '{namespace_name}.{table_name}' has storage outside the tenant namespace prefix"
                )

    async def record_validation_failure(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
        username: str,
        actor: str,
        message: str,
    ) -> None:
        """Record a validation failure that happens before a grant row exists."""
        await self._store.append_event(
            tenant_name=tenant_name,
            namespace_parts=namespace_parts,
            username=username,
            event_type=EVENT_VALIDATION_FAILED,
            actor=actor,
            message=message,
        )

    async def reconcile_tenant_membership(
        self,
        username: str,
        tenant_name: str,
        permission: str | None,
        actor: str = "system",
    ) -> NamespaceAclUserSyncResult:
        """Shadow or reactivate namespace ACL grants after tenant membership changes."""
        grants = await self._store.list_active_grants_for_user(
            username,
            statuses=(
                GRANT_STATUS_PENDING,
                GRANT_STATUS_ACTIVE,
                GRANT_STATUS_SHADOWED,
                GRANT_STATUS_SYNC_ERROR,
            ),
        )
        for grant in grants:
            if grant.tenant_name != tenant_name:
                continue
            should_shadow = _tenant_permission_shadows_grant(
                permission,
                grant.access_level,
            )
            if should_shadow and grant.status != GRANT_STATUS_SHADOWED:
                await self._store.update_grant_status(
                    grant_id=grant.id,
                    status=GRANT_STATUS_SHADOWED,
                    actor=actor,
                    last_synced_at=None,
                    last_sync_error=None,
                    event_type=EVENT_GRANT_SHADOWED,
                    message="grant shadowed by tenant membership",
                )
            elif not should_shadow and grant.status == GRANT_STATUS_SHADOWED:
                await self._store.update_grant_status(
                    grant_id=grant.id,
                    status=GRANT_STATUS_PENDING,
                    actor=actor,
                    last_synced_at=None,
                    last_sync_error=None,
                    event_type=EVENT_GRANT_ACTIVATED,
                    message="grant reactivated after tenant membership change",
                )
        return await self.reconcile_user(username)

    async def delete_tenant_cascade(
        self,
        tenant_name: str,
        actor: str = "system",
    ) -> NamespaceAclCascadeResult:
        """Revoke namespace ACL grants and roles for a deleted tenant."""
        grants = [
            grant
            for grant in await self._store.list_grants_for_tenant(tenant_name)
            if grant.revoked_at is None
        ]
        affected_users = sorted({grant.username for grant in grants})
        revoked_count = 0
        for grant in grants:
            revoked = await self._store.revoke_grant(
                tenant_name=grant.tenant_name,
                namespace_parts=grant.namespace_parts,
                username=grant.username,
                actor=actor,
                message=f"tenant '{tenant_name}' was deleted",
            )
            if revoked is not None:
                revoked_count += 1

        for username in affected_users:
            await self.reconcile_user(username)

        deleted_roles: list[str] = []
        for role in await self._store.list_roles_for_tenant(tenant_name):
            await self._polaris_service.delete_principal_role(role.principal_role_name)
            deleted_roles.append(role.principal_role_name)

        return NamespaceAclCascadeResult(
            revoked_grants=revoked_count,
            reconciled_users=tuple(affected_users),
            deleted_principal_roles=tuple(deleted_roles),
        )

    async def delete_user_cascade(
        self,
        username: str,
        actor: str = "system",
    ) -> NamespaceAclCascadeResult:
        """Revoke namespace ACL grants before a user is deleted."""
        grants = await self.list_grants_for_user(username)
        revoked_count = 0
        for grant in grants:
            revoked = await self._store.revoke_grant(
                tenant_name=grant.tenant_name,
                namespace_parts=grant.namespace_parts,
                username=grant.username,
                actor=actor,
                message=f"user '{username}' was deleted",
            )
            if revoked is not None:
                revoked_count += 1

        await self.reconcile_user(username)
        return NamespaceAclCascadeResult(
            revoked_grants=revoked_count,
            reconciled_users=(username,),
            deleted_principal_roles=(),
        )

    async def _ensure_polaris_assignment(
        self,
        username: str,
        grant: NamespaceAclGrantRecord,
        role: NamespaceAclRoleRecord,
    ) -> None:
        await self._polaris_service.ensure_namespace_acl_role_bindings(
            catalog=grant.catalog_name,
            catalog_role=role.catalog_role_name,
            principal_role=role.principal_role_name,
            namespace=grant.namespace_parts,
            access_level=grant.access_level,
        )
        await self._polaris_service.grant_principal_role_to_principal(
            username,
            role.principal_role_name,
        )

    async def _revoke_stale_namespace_roles(
        self,
        username: str,
        expected_principal_roles: set[str],
    ) -> list[str]:
        assigned_roles = await self._polaris_service.get_principal_roles_for_principal(
            username
        )
        stale_roles = [
            role
            for role in assigned_roles
            if _is_namespace_acl_principal_role(role)
            and role not in expected_principal_roles
        ]
        for role in stale_roles:
            await self._polaris_service.revoke_principal_role_from_principal(
                username,
                role,
            )
        return stale_roles

    async def _mark_grants_active(self, grant_ids: Sequence[str]) -> None:
        now = datetime.now(UTC)
        for grant_id in grant_ids:
            await self._store.update_grant_status(
                grant_id=grant_id,
                status=GRANT_STATUS_ACTIVE,
                actor="system",
                last_synced_at=now,
                last_sync_error=None,
                event_type=EVENT_SYNC_HEALED,
            )

    async def _mark_grant_failed(
        self,
        grant: NamespaceAclGrantRecord,
        message: str,
    ) -> NamespaceAclGrantSyncFailure:
        await self._store.update_grant_status(
            grant_id=grant.id,
            status=GRANT_STATUS_SYNC_ERROR,
            actor="system",
            last_synced_at=None,
            last_sync_error=message,
            event_type=EVENT_SYNC_FAILED,
            message=message,
        )
        logger.warning(
            "Namespace ACL grant %s for user %s failed reconciliation: %s",
            grant.id,
            grant.username,
            message,
        )
        return NamespaceAclGrantSyncFailure(
            grant_id=grant.id,
            username=grant.username,
            message=message,
        )

    async def _mark_policy_size_failures(
        self,
        grants: Sequence[NamespaceAclGrantRecord],
        policy_size_bytes: int,
    ) -> list[NamespaceAclGrantSyncFailure]:
        message = (
            f"namespace ACL policy would be {policy_size_bytes} bytes, "
            f"exceeding configured limit of {self._max_policy_bytes}"
        )
        failures = []
        for grant in grants:
            failures.append(await self._mark_grant_failed(grant, message))
        return failures

    async def _fail_all_grants(
        self,
        username: str,
        grants: Sequence[NamespaceAclGrantRecord],
        policy_name: str,
        message: str,
    ) -> NamespaceAclUserSyncResult:
        failures = []
        for grant in grants:
            failures.append(await self._mark_grant_failed(grant, message))
        await self._policy_manager.detach_and_delete_user_policy(policy_name, username)
        return NamespaceAclUserSyncResult(
            username=username,
            policy_name=policy_name,
            synced_grants=(),
            failed_grants=tuple(failures),
            revoked_stale_roles=(),
            policy_size_bytes=0,
        )

    def _allowed_namespace_location_prefixes(
        self,
        tenant_name: str,
        namespace_parts: Sequence[str],
    ) -> tuple[str, ...]:
        namespace_path = "/".join(normalize_namespace_parts(namespace_parts))
        root = (
            f"{self._minio_config.default_bucket}/"
            f"{self._minio_config.tenant_sql_warehouse_prefix}/"
            f"{tenant_name}/{ICEBERG_STORAGE_SUBDIRECTORY}/{namespace_path}/"
        )
        return (f"s3a://{root}", f"s3://{root}")


def _is_namespace_acl_principal_role(role_name: str) -> bool:
    return role_name.startswith(
        NAMESPACE_ACL_PRINCIPAL_ROLE_PREFIX
    ) and role_name.endswith(NAMESPACE_ACL_PRINCIPAL_ROLE_SUFFIX)


def _tenant_permission_shadows_grant(
    permission: str | None,
    access_level: str,
) -> bool:
    if permission == "read_write":
        return True
    return permission == "read_only" and access_level == "read"


def _table_locations(table: dict[str, Any]) -> tuple[str, ...]:
    locations: list[str] = []
    for key in ("metadata-location", "metadataLocation", "location"):
        value = table.get(key)
        if isinstance(value, str):
            locations.append(value)

    metadata = table.get("metadata")
    if isinstance(metadata, dict):
        for key in ("location", "metadata-location", "metadataLocation"):
            value = metadata.get(key)
            if isinstance(value, str):
                locations.append(value)

    return tuple(dict.fromkeys(locations))
