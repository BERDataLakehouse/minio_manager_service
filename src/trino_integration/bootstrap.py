"""Automatic bootstrap helpers for Polaris-backed Trino tenant catalogs."""

from minio.managers.user_manager import GLOBAL_USER_GROUP
from service.app_state import AppState
from trino_integration.service_identity import ensure_tenant_trino_service


async def ensure_globalusers_trino_catalog(app_state: AppState) -> str | None:
    """Ensure the default ``globalusers`` tenant is visible in Trino.

    ``globalusers`` is special: it is auto-created by user bootstrap rather
    than by the admin create-group route. The normal create-group route already
    provisions Trino, but this path needs an explicit repair step so a clean
    environment does not require the bulk backfill notebook.

    Returns the Trino catalog alias when reconciliation was performed, otherwise
    ``None``.
    """
    if not await app_state.group_manager.resource_exists(GLOBAL_USER_GROUP):
        return None

    if await app_state.trino_catalog_reconciler.tenant_catalog_exists(
        GLOBAL_USER_GROUP
    ):
        return None

    await ensure_tenant_trino_service(
        group_name=GLOBAL_USER_GROUP,
        user_manager=app_state.user_manager,
        group_manager=app_state.group_manager,
        polaris_group_manager=app_state.polaris_group_manager,
        polaris_user_manager=app_state.polaris_user_manager,
        s3_credential_store=app_state.s3_credential_store,
        polaris_credential_store=app_state.polaris_credential_store,
    )
    return await app_state.trino_catalog_reconciler.reconcile_tenant(GLOBAL_USER_GROUP)
