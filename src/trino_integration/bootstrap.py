"""Automatic bootstrap helpers for Polaris-backed Trino tenant catalogs.

The global Trino service identity is pre-provisioned by an admin. This
helper makes sure the ``globalusers`` catalog is registered in the Trino
coordinator on first user credential fetch — useful for a freshly restarted
stack where no admin has explicitly called the bulk reconcile endpoint yet.
"""

import logging
import time

from minio.managers.user_manager import GLOBAL_USER_GROUP
from service.app_state import AppState

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
    than by the admin create-group route. The create-group route reconciles
    automatically, but on a cold-start path (Trino coordinator restart,
    fresh local stack) the catalog may be missing even though Polaris
    artifacts exist. This helper re-reconciles in that case so a user's
    first credential fetch repairs the catalog. No per-tenant Polaris or
    IAM grants are issued — the global Trino service identity already has
    broad access from bootstrap.

    Returns the Trino catalog alias when reconciliation was performed,
    otherwise ``None``.
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
