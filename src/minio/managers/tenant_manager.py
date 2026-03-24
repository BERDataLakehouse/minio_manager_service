"""Business logic for tenant metadata, steward management, and member operations.

Coordinates between TenantMetadataStore (PostgreSQL), GroupManager (MinIO),
and KBaseUserProfileClient (KBase Auth + local profiles).
"""

import logging

from fastapi import HTTPException, status

from src.minio.clients.kbase_profile_client import KBaseUserProfileClient
from src.minio.managers.group_manager import GroupManager
from src.minio.models.minio_config import MinIOConfig
from src.minio.models.tenant import (
    TenantDetailResponse,
    TenantMemberResponse,
    TenantMetadataResponse,
    TenantMetadataUpdate,
    TenantStoragePaths,
    TenantStewardResponse,
    TenantSummaryResponse,
    UserProfile,
)
from src.minio.stores.tenant_metadata_store import TenantMetadataStore
from src.service.kb_auth import AdminPermission, KBaseUser

logger = logging.getLogger(__name__)

# Groups to exclude from tenant listings
SYSTEM_GROUPS: set[str] = {"globalusers"}


def _is_tenant_group(name: str) -> bool:
    """Return True if a group name represents a base tenant (not system or RO variant)."""
    return name not in SYSTEM_GROUPS and not name.endswith("ro")


class TenantManager:
    """Coordinates tenant operations across metadata store, MinIO groups, and profiles."""

    def __init__(
        self,
        metadata_store: TenantMetadataStore,
        group_manager: GroupManager,
        profile_client: KBaseUserProfileClient,
        minio_config: MinIOConfig,
    ) -> None:
        self.metadata_store = metadata_store
        self._group_manager = group_manager
        self._profile_client = profile_client
        self._config = minio_config

    # ── Tenant listing ───────────────────────────────────────────────────

    async def list_tenants(
        self, requesting_user: str, token: str
    ) -> list[TenantSummaryResponse]:
        """List all tenants with summary info for the requesting user."""
        all_groups = await self._group_manager.list_resources()
        tenant_names = [g for g in all_groups if _is_tenant_group(g)]

        # Pre-fetch all metadata in one query
        metadata_map = {
            m["tenant_name"]: m for m in await self.metadata_store.list_metadata()
        }

        # Pre-fetch steward tenants for the requesting user
        steward_tenants = set(
            await self.metadata_store.get_steward_tenants(requesting_user)
        )

        summaries = []
        for name in sorted(tenant_names):
            members = await self._group_manager.get_group_members(name)
            ro_members = []
            ro_name = f"{name}ro"
            if ro_name in all_groups:
                ro_members = await self._group_manager.get_group_members(ro_name)

            all_members = set(members) | set(ro_members)
            meta = metadata_map.get(name, {})

            summaries.append(
                TenantSummaryResponse(
                    tenant_name=name,
                    display_name=meta.get("display_name"),
                    description=meta.get("description"),
                    member_count=len(all_members),
                    is_member=requesting_user in all_members,
                    is_steward=name in steward_tenants,
                )
            )
        return summaries

    # ── Tenant detail ────────────────────────────────────────────────────

    async def get_tenant_detail(
        self, tenant_name: str, requesting_user: KBaseUser, token: str
    ) -> TenantDetailResponse:
        """Get full tenant detail with metadata, stewards, members, and profiles."""
        await self._require_group_exists(tenant_name)

        # Gather data
        rw_members = await self._group_manager.get_group_members(tenant_name)
        ro_name = f"{tenant_name}ro"
        ro_members = []
        try:
            ro_members = await self._group_manager.get_group_members(ro_name)
        except Exception:
            pass  # RO group may not exist

        rw_set = set(rw_members)
        all_members = rw_set | set(ro_members)

        # Authorization: admin, steward, or member
        is_admin = requesting_user.admin_perm == AdminPermission.FULL
        is_steward = await self.metadata_store.is_steward(
            tenant_name, requesting_user.user
        )
        if not is_admin and not is_steward and requesting_user.user not in all_members:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You must be a member, steward, or admin to view tenant details",
            )

        # Metadata (lazy-create if missing)
        meta = await self.ensure_metadata(tenant_name, created_by="system")

        # Stewards
        steward_rows = await self.metadata_store.get_stewards(tenant_name)
        steward_usernames = {s["username"] for s in steward_rows}

        # Profiles
        all_usernames = list(all_members | steward_usernames)
        profiles = await self._profile_client.get_user_profiles(all_usernames, token)

        # Build member responses
        members = self._build_member_list(
            rw_set, ro_members, steward_usernames, profiles
        )

        # Build steward responses
        stewards = [
            TenantStewardResponse(
                username=s["username"],
                display_name=profiles.get(
                    s["username"], UserProfile(username=s["username"])
                ).display_name,
                email=profiles.get(
                    s["username"], UserProfile(username=s["username"])
                ).email,
                assigned_by=s["assigned_by"],
                assigned_at=s["assigned_at"],
            )
            for s in steward_rows
        ]

        # Build metadata response
        metadata_resp = self._meta_dict_to_response(meta)

        # Storage paths
        bucket = self._config.default_bucket
        storage_paths = TenantStoragePaths(
            general_warehouse=f"s3a://{bucket}/{self._config.tenant_general_warehouse_prefix}/{tenant_name}/",
            sql_warehouse=f"s3a://{bucket}/{self._config.tenant_sql_warehouse_prefix}/{tenant_name}/",
            namespace_prefix=f"{tenant_name}_",
        )

        return TenantDetailResponse(
            metadata=metadata_resp,
            stewards=stewards,
            members=members,
            member_count=len(all_members),
            storage_paths=storage_paths,
        )

    # ── Tenant members ───────────────────────────────────────────────────

    async def get_tenant_members(
        self, tenant_name: str, requesting_user: KBaseUser, token: str
    ) -> list[TenantMemberResponse]:
        """List all members of a tenant with profiles and access levels."""
        await self._require_group_exists(tenant_name)

        rw_members = await self._group_manager.get_group_members(tenant_name)
        ro_members = []
        try:
            ro_members = await self._group_manager.get_group_members(f"{tenant_name}ro")
        except Exception:
            pass

        rw_set = set(rw_members)
        all_members = rw_set | set(ro_members)

        # Authorization
        is_admin = requesting_user.admin_perm == AdminPermission.FULL
        is_steward = await self.metadata_store.is_steward(
            tenant_name, requesting_user.user
        )
        if not is_admin and not is_steward and requesting_user.user not in all_members:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You must be a member, steward, or admin to view tenant members",
            )

        steward_rows = await self.metadata_store.get_stewards(tenant_name)
        steward_usernames = {s["username"] for s in steward_rows}

        all_usernames = list(all_members)
        profiles = await self._profile_client.get_user_profiles(all_usernames, token)

        return self._build_member_list(rw_set, ro_members, steward_usernames, profiles)

    async def add_member(
        self,
        tenant_name: str,
        username: str,
        permission: str,
        token: str,
    ) -> TenantMemberResponse:
        """Add a user to a tenant with the given permission level."""
        await self._require_group_exists(tenant_name)

        target_group = tenant_name if permission == "read_write" else f"{tenant_name}ro"
        await self._group_manager.add_user_to_group(username, target_group)

        profiles = await self._profile_client.get_user_profiles([username], token)
        profile = profiles.get(username, UserProfile(username=username))

        steward_usernames = {
            s["username"] for s in await self.metadata_store.get_stewards(tenant_name)
        }

        logger.info("Added %s to tenant %s (%s)", username, tenant_name, permission)
        return TenantMemberResponse(
            username=username,
            display_name=profile.display_name,
            email=profile.email,
            access_level=permission,
            is_steward=username in steward_usernames,
        )

    async def remove_member(
        self,
        tenant_name: str,
        username: str,
        acting_user: KBaseUser,
    ) -> None:
        """Remove a user from a tenant. Enforces steward constraints."""
        await self._require_group_exists(tenant_name)

        is_admin = acting_user.admin_perm == AdminPermission.FULL
        is_target_steward = await self.metadata_store.is_steward(tenant_name, username)

        if not is_admin:
            # Steward cannot remove self
            if acting_user.user == username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Stewards cannot remove themselves. Ask an admin to reassign stewardship.",
                )
            # Steward cannot remove other stewards
            if is_target_steward:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only admins can remove stewards from a tenant",
                )

        # Remove from both RW and RO groups
        try:
            await self._group_manager.remove_user_from_group(username, tenant_name)
        except Exception:
            pass
        try:
            await self._group_manager.remove_user_from_group(
                username, f"{tenant_name}ro"
            )
        except Exception:
            pass

        # Cascade: remove steward assignment if user was a steward
        if is_target_steward:
            await self.metadata_store.remove_steward(tenant_name, username)
            logger.info(
                "Cascaded steward removal for %s from tenant %s", username, tenant_name
            )

        logger.info("Removed %s from tenant %s", username, tenant_name)

    # ── Tenant metadata ──────────────────────────────────────────────────

    async def update_metadata(
        self,
        tenant_name: str,
        update: TenantMetadataUpdate,
        updated_by: str,
    ) -> TenantMetadataResponse:
        """Update tenant metadata (display_name, description, organization)."""
        await self._require_group_exists(tenant_name)
        await self.ensure_metadata(tenant_name, created_by=updated_by)

        result = await self.metadata_store.update_metadata(
            tenant_name,
            updated_by,
            display_name=update.display_name,
            description=update.description,
            organization=update.organization,
        )
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tenant '{tenant_name}' not found",
            )
        return self._meta_dict_to_response(result)

    async def create_metadata(
        self,
        tenant_name: str,
        created_by: str,
        update: TenantMetadataUpdate | None = None,
    ) -> TenantMetadataResponse:
        """Create tenant metadata (idempotent).

        If metadata already exists, returns the existing record unchanged.
        """
        result = await self.metadata_store.create_metadata(
            tenant_name,
            created_by,
            display_name=update.display_name if update else None,
            description=update.description if update else None,
            organization=update.organization if update else None,
        )
        if result is None:
            result = await self.metadata_store.get_metadata(tenant_name)
        return self._meta_dict_to_response(result)

    async def delete_metadata(self, tenant_name: str) -> None:
        """Delete tenant metadata and cascaded steward assignments."""
        deleted = await self.metadata_store.delete_metadata(tenant_name)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tenant metadata for '{tenant_name}' not found",
            )
        logger.info("Deleted metadata for tenant %s", tenant_name)

    async def ensure_metadata(self, tenant_name: str, created_by: str) -> dict:
        """Ensure metadata exists for a tenant (lazy backfill). Returns the metadata dict."""
        meta = await self.metadata_store.get_metadata(tenant_name)
        if meta is not None:
            return meta
        result = await self.metadata_store.create_metadata(tenant_name, created_by)
        # ON CONFLICT DO NOTHING may return None if concurrent insert won
        if result is None:
            return await self.metadata_store.get_metadata(tenant_name)
        return result

    # ── Steward management ───────────────────────────────────────────────

    async def get_stewards(
        self, tenant_name: str, requesting_user: KBaseUser, token: str
    ) -> list[TenantStewardResponse]:
        """Get stewards with profile info. Requires member, steward, or admin."""
        await self._require_group_exists(tenant_name)

        # Authorization: admin, steward, or member
        rw_members = await self._group_manager.get_group_members(tenant_name)
        ro_members = []
        try:
            ro_members = await self._group_manager.get_group_members(f"{tenant_name}ro")
        except Exception:
            pass
        all_members = set(rw_members) | set(ro_members)

        is_admin = requesting_user.admin_perm == AdminPermission.FULL
        is_steward = await self.metadata_store.is_steward(
            tenant_name, requesting_user.user
        )
        if not is_admin and not is_steward and requesting_user.user not in all_members:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You must be a member, steward, or admin to view tenant stewards",
            )

        steward_rows = await self.metadata_store.get_stewards(tenant_name)
        usernames = [s["username"] for s in steward_rows]
        profiles = await self._profile_client.get_user_profiles(usernames, token)

        return [
            TenantStewardResponse(
                username=s["username"],
                display_name=profiles.get(
                    s["username"], UserProfile(username=s["username"])
                ).display_name,
                email=profiles.get(
                    s["username"], UserProfile(username=s["username"])
                ).email,
                assigned_by=s["assigned_by"],
                assigned_at=s["assigned_at"],
            )
            for s in steward_rows
        ]

    async def add_steward(
        self,
        tenant_name: str,
        username: str,
        assigned_by: str,
        token: str,
    ) -> TenantStewardResponse:
        """Assign a user as steward. User must be a member of the tenant."""
        await self._require_group_exists(tenant_name)
        await self.ensure_metadata(tenant_name, created_by=assigned_by)

        # Verify user is a member
        is_rw_member = await self._group_manager.is_user_in_group(username, tenant_name)
        is_ro_member = False
        try:
            is_ro_member = await self._group_manager.is_user_in_group(
                username, f"{tenant_name}ro"
            )
        except Exception:
            pass

        if not is_rw_member and not is_ro_member:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User '{username}' must be a member of tenant '{tenant_name}' before being assigned as steward",
            )

        row = await self.metadata_store.add_steward(tenant_name, username, assigned_by)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"User '{username}' is already a steward of tenant '{tenant_name}'",
            )
        profiles = await self._profile_client.get_user_profiles([username], token)
        profile = profiles.get(username, UserProfile(username=username))

        logger.info("Assigned %s as steward of tenant %s", username, tenant_name)
        return TenantStewardResponse(
            username=username,
            display_name=profile.display_name,
            email=profile.email,
            assigned_by=row["assigned_by"],
            assigned_at=row["assigned_at"],
        )

    async def remove_steward(self, tenant_name: str, username: str) -> None:
        """Remove steward assignment. Does not remove from tenant."""
        removed = await self.metadata_store.remove_steward(tenant_name, username)
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{username}' is not a steward of tenant '{tenant_name}'",
            )
        logger.info("Removed %s as steward of tenant %s", username, tenant_name)

    # ── Private helpers ──────────────────────────────────────────────────

    async def _require_group_exists(self, tenant_name: str) -> None:
        """Raise 404 if the MinIO group does not exist."""
        if not await self._group_manager.resource_exists(tenant_name):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tenant '{tenant_name}' not found",
            )

    def _build_member_list(
        self,
        rw_set: set[str],
        ro_members: list[str],
        steward_usernames: set[str],
        profiles: dict[str, UserProfile],
    ) -> list[TenantMemberResponse]:
        """Build member list with access levels. RW takes precedence over RO."""
        members = []
        seen = set()

        # RW members first
        for username in sorted(rw_set):
            profile = profiles.get(username, UserProfile(username=username))
            members.append(
                TenantMemberResponse(
                    username=username,
                    display_name=profile.display_name,
                    email=profile.email,
                    access_level="read_write",
                    is_steward=username in steward_usernames,
                )
            )
            seen.add(username)

        # RO-only members
        for username in sorted(ro_members):
            if username in seen:
                continue
            profile = profiles.get(username, UserProfile(username=username))
            members.append(
                TenantMemberResponse(
                    username=username,
                    display_name=profile.display_name,
                    email=profile.email,
                    access_level="read_only",
                    is_steward=username in steward_usernames,
                )
            )

        return members

    @staticmethod
    def _meta_dict_to_response(meta: dict) -> TenantMetadataResponse:
        return TenantMetadataResponse(
            tenant_name=meta["tenant_name"],
            display_name=meta.get("display_name"),
            description=meta.get("description"),
            organization=meta.get("organization"),
            created_by=meta["created_by"],
            created_at=meta["created_at"],
            updated_at=meta["updated_at"],
            updated_by=meta.get("updated_by"),
        )
