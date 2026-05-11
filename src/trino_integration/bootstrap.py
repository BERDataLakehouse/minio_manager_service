"""Automatic bootstrap helpers for Polaris-backed Trino tenant catalogs."""

import logging
import time

from minio.managers.user_manager import GLOBAL_USER_GROUP
from service.app_state import AppState
from trino_integration.service_identity import ensure_tenant_trino_service

logger = logging.getLogger(__name__)

GLOBALUSERS_TRINO_BOOTSTRAP_CACHE_SECONDS = 300

_globalusers_trino_bootstrap_checked_until = 0.0


def _globalusers_trino_bootstrap_cached() -> bool:
    return time.monotonic() < _globalusers_trino_bootstrap_checked_until


def _mark_globalusers_trino_bootstrap_checked() -> None:
    global _globalusers_trino_bootstrap_checked_until
    _globalusers_trino_bootstrap_checked_until = (
        time.monotonic() + GLOBALUSERS_TRINO_BOOTSTRAP_CACHE_SECONDS
    )


def _reset_globalusers_trino_bootstrap_cache() -> None:
    global _globalusers_trino_bootstrap_checked_until
    _globalusers_trino_bootstrap_checked_until = 0.0


async def ensure_globalusers_trino_catalog(app_state: AppState) -> str | None:
    """Ensure the default ``globalusers`` tenant is visible in Trino.

    ``globalusers`` is special: it is auto-created by user bootstrap rather
    than by the admin create-group route. The normal create-group route already
    provisions Trino, but this path needs an explicit repair step so a clean
    environment does not require the bulk backfill notebook.

    Returns the Trino catalog alias when reconciliation was performed, otherwise
    ``None``.
    """
    if _globalusers_trino_bootstrap_cached():
        return None

    try:
        if not await app_state.group_manager.resource_exists(GLOBAL_USER_GROUP):
            return None

        if await app_state.trino_catalog_reconciler.tenant_catalog_exists(
            GLOBAL_USER_GROUP
        ):
            _mark_globalusers_trino_bootstrap_checked()
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
        alias = await app_state.trino_catalog_reconciler.reconcile_tenant(
            GLOBAL_USER_GROUP
        )
        _mark_globalusers_trino_bootstrap_checked()
        return alias
    except Exception as exc:  # noqa: BLE001 - never break user credential bootstrap
        logger.warning(
            "Failed to ensure default Trino tenant catalog '%s'; continuing "
            "credential bootstrap without Trino repair: %s",
            GLOBAL_USER_GROUP,
            exc,
        )
        return None
