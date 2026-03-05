import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from ..service import app_state
from ..service.dependencies import auth
from ..service.kb_auth import AdminPermission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/polaris")


@router.post("/user_provision/{username}", response_model=Dict[str, Any])
async def provision_polaris_user(
    username: str,
    app_state_obj: app_state.AppState = Depends(app_state.get_app_state),
    authenticated_user=Depends(auth),  # Any authenticated user
):
    """
    Provision a user's Polaris environment and return fresh credentials.

    This is the single entry point for Polaris user setup. It is fully idempotent:
    all create operations silently succeed if the resource already exists, and
    credentials are rotated on every call so the caller always gets a valid pair.

    Steps performed:
    1. Create personal Iceberg catalog (``user_{username}``)
    2. Create Polaris principal for the user
    3. Create ``catalog_admin`` catalog role with ``CATALOG_MANAGE_CONTENT`` privilege
    4. Create ``{username}_role`` principal role and wire it to the catalog role
    5. Rotate credentials — returns a fresh ``client_id`` / ``client_secret``
    6. Discover tenant catalog access from group memberships

    Authorization:
    - Authenticated users can provision themselves.
    - Admins (``AdminPermission.FULL``) can provision any user.

    Returns:
        ``client_id``, ``client_secret``, ``personal_catalog``, ``tenant_catalogs``
    """
    # Self-provisioning: users can only provision their own catalog
    if (
        authenticated_user.user != username
        and authenticated_user.admin_perm != AdminPermission.FULL
    ):
        raise HTTPException(
            status_code=403,
            detail="You can only provision your own Polaris catalog",
        )

    polaris = app_state_obj.polaris_service

    try:
        # Use SQL warehouse path with /iceberg/ subdirectory.
        # Iceberg uses Polaris for catalog-level isolation instead of governance prefixes.
        # The /iceberg/ path has its own IAM statement separate from the u_{username}__*
        # governed path, added by policy_creator._create_default_user_home_policy().
        user_config = app_state_obj.user_manager.config
        storage_location = f"s3a://{user_config.default_bucket}/{user_config.users_sql_warehouse_prefix}/{username}/iceberg/"

        # All steps are idempotent — create_* methods return existing entities on 409,
        # and grant_* calls are wrapped in try/except to handle "already granted" (500).
        catalog_name = f"user_{username}"

        # 1. Create personal catalog
        await polaris.create_catalog(
            name=catalog_name, storage_location=storage_location
        )

        # 2. Create principal
        await polaris.create_principal(name=username)

        # 3. Create catalog_admin role in the personal catalog
        catalog_role = "catalog_admin"
        await polaris.create_catalog_role(catalog=catalog_name, role_name=catalog_role)

        # 4. Grant CATALOG_MANAGE_CONTENT on the catalog to the catalog role
        await polaris.grant_catalog_privilege(
            catalog=catalog_name,
            role_name=catalog_role,
            privilege="CATALOG_MANAGE_CONTENT",
        )

        # 5. Create a principal role for the user
        principal_role = f"{username}_role"
        await polaris.create_principal_role(role_name=principal_role)

        # 6. Assign the catalog role to the principal role
        await polaris.grant_catalog_role_to_principal_role(
            catalog=catalog_name,
            catalog_role=catalog_role,
            principal_role=principal_role,
        )

        # 7. Assign the principal role to the principal
        await polaris.grant_principal_role_to_principal(
            principal=username, principal_role=principal_role
        )

        # 8. Fetch credentials (client_id, client_secret)
        # Because we cannot securely store client_secret inside Minio Manager without complexity,
        # we will simply ROTATE the credentials at this point so we can give them to JupyterHub.
        # In this architecture, JupyterHub gets the credentials and injects them into the pod ENV.
        creds = await polaris.rotate_principal_credentials(name=username)

    except Exception as e:
        logger.exception(f"Failed to provision Polaris catalog for {username}")
        raise HTTPException(
            status_code=500, detail=f"Failed to provision Polaris catalog: {str(e)}"
        )

    # Check for group memberships to determine tenant catalogs and grant access.
    # This must happen AFTER the principal is created above, because
    # grant_principal_role_to_principal requires the principal to exist.
    user_groups = await app_state_obj.group_manager.get_user_groups(username)
    group_config = app_state_obj.user_manager.config
    tenant_catalogs = []
    for g in user_groups:
        if g.endswith("ro"):
            base_group = g[:-2]
            tenant_catalogs.append(f"tenant_{base_group}")

            # Ensure the tenant catalog and roles exist (idempotent).
            # This handles groups that were created before Polaris was integrated.
            storage = f"s3a://{group_config.default_bucket}/{group_config.tenant_sql_warehouse_prefix}/{base_group}/iceberg/"
            await polaris.ensure_tenant_catalog(base_group, storage)

            # Grant read-only principal role for this group
            await polaris.grant_principal_role_to_principal(
                username, f"{base_group}ro_member"
            )
        else:
            tenant_catalogs.append(f"tenant_{g}")

            # Ensure the tenant catalog and roles exist (idempotent).
            storage = f"s3a://{group_config.default_bucket}/{group_config.tenant_sql_warehouse_prefix}/{g}/iceberg/"
            await polaris.ensure_tenant_catalog(g, storage)

            # Grant read-write principal role for this group
            await polaris.grant_principal_role_to_principal(username, f"{g}_member")

    # Remove duplicates but preserve order
    tenant_catalogs = list(dict.fromkeys(tenant_catalogs))

    return {
        "client_id": creds.get("credentials", {}).get("clientId"),
        "client_secret": creds.get("credentials", {}).get("clientSecret"),
        "personal_catalog": catalog_name,
        "tenant_catalogs": tenant_catalogs,
    }
