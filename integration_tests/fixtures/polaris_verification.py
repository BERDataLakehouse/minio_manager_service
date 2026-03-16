"""
Polaris state verification fixtures for integration tests.

Provides a SyncPolarisVerifier that wraps PolarisService with synchronous
wrappers for use in standard (non-async) pytest test functions.
"""

import asyncio
import os
import sys
import logging
from pathlib import Path
from typing import List

import pytest

# Add parent directories to path for imports
_base_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_base_path))
sys.path.insert(0, str(_base_path / "src"))

logger = logging.getLogger(__name__)


class PolarisVerifier:
    """
    Async Polaris state verification helper.

    Wraps PolarisService with convenience methods that return simple
    booleans / lists usable in assertion statements.
    """

    def __init__(self, polaris_uri: str, credential: str, minio_endpoint: str):
        from src.polaris.polaris_service import PolarisService

        self._svc = PolarisService(
            polaris_uri=polaris_uri,
            root_credential=credential,
            minio_endpoint=minio_endpoint,
        )

    # ------------------------------------------------------------------ #
    # Catalog helpers                                                      #
    # ------------------------------------------------------------------ #

    async def catalog_exists(self, name: str) -> bool:
        """Return True if the named catalog exists in Polaris."""
        try:
            await self._svc.get_catalog(name)
            return True
        except Exception:
            return False

    async def get_catalog(self, name: str):
        """Return the raw catalog dict, or None if not found."""
        try:
            return await self._svc.get_catalog(name)
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # Principal helpers                                                    #
    # ------------------------------------------------------------------ #

    async def principal_exists(self, name: str) -> bool:
        """Return True if the named principal exists in Polaris."""
        try:
            await self._svc.get_principal(name)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Principal role helpers                                               #
    # ------------------------------------------------------------------ #

    async def principal_role_exists(self, role_name: str) -> bool:
        """Return True if the principal role exists in Polaris."""
        try:
            await self._svc.get_principal_role(role_name)
            return True
        except Exception:
            return False

    async def get_roles_for_principal(self, principal: str) -> List[str]:
        """Return list of principal role names assigned to a principal."""
        try:
            return await self._svc.get_principal_roles_for_principal(principal)
        except Exception:
            return []

    async def is_role_assigned_to_principal(
        self, principal: str, role_name: str
    ) -> bool:
        """Return True if the role is assigned to the given principal."""
        roles = await self.get_roles_for_principal(principal)
        return role_name in roles

    # ------------------------------------------------------------------ #
    # Cleanup helpers (for use in test teardown)                          #
    # ------------------------------------------------------------------ #

    async def cleanup_catalog(self, name: str) -> None:
        """Best-effort delete a catalog (ignores errors)."""
        try:
            await self._svc.delete_catalog(name)
        except Exception as e:
            logger.debug(f"cleanup_catalog({name}): {e}")

    async def cleanup_principal(self, name: str) -> None:
        """Best-effort delete a principal (ignores errors)."""
        try:
            await self._svc.delete_principal(name)
        except Exception as e:
            logger.debug(f"cleanup_principal({name}): {e}")

    async def cleanup_principal_role(self, role_name: str) -> None:
        """Best-effort delete a principal role (ignores errors)."""
        try:
            await self._svc.delete_principal_role(role_name)
        except Exception as e:
            logger.debug(f"cleanup_principal_role({role_name}): {e}")

    async def drop_tenant_catalog(self, group_name: str) -> None:
        """Best-effort drop a tenant catalog + its roles (ignores errors)."""
        try:
            await self._svc.drop_tenant_catalog(group_name)
        except Exception as e:
            logger.debug(f"drop_tenant_catalog({group_name}): {e}")


class SyncPolarisVerifier:
    """
    Synchronous wrapper around PolarisVerifier for use in standard pytest tests.

    Uses ``asyncio.run`` to bridge into async Polaris API calls.
    """

    def __init__(self, async_verifier: PolarisVerifier):
        self._v = async_verifier

    def catalog_exists(self, name: str) -> bool:
        return asyncio.run(self._v.catalog_exists(name))

    def get_catalog(self, name: str):
        return asyncio.run(self._v.get_catalog(name))

    def principal_exists(self, name: str) -> bool:
        return asyncio.run(self._v.principal_exists(name))

    def principal_role_exists(self, role_name: str) -> bool:
        return asyncio.run(self._v.principal_role_exists(role_name))

    def get_roles_for_principal(self, principal: str) -> List[str]:
        return asyncio.run(self._v.get_roles_for_principal(principal))

    def is_role_assigned_to_principal(self, principal: str, role_name: str) -> bool:
        return asyncio.run(self._v.is_role_assigned_to_principal(principal, role_name))

    def cleanup_catalog(self, name: str) -> None:
        asyncio.run(self._v.cleanup_catalog(name))

    def cleanup_principal(self, name: str) -> None:
        asyncio.run(self._v.cleanup_principal(name))

    def cleanup_principal_role(self, role_name: str) -> None:
        asyncio.run(self._v.cleanup_principal_role(role_name))

    def drop_tenant_catalog(self, group_name: str) -> None:
        asyncio.run(self._v.drop_tenant_catalog(group_name))


@pytest.fixture(scope="session")
def polaris_verifier():
    """
    Session-scoped Polaris verifier fixture.

    Reads POLARIS_CATALOG_URI and POLARIS_CREDENTIAL from environment,
    exactly as the minio-manager service does.  If these are not set
    (Polaris is not running), the fixture skips the test.
    """
    polaris_uri = os.getenv("POLARIS_CATALOG_URI")
    credential = os.getenv("POLARIS_CREDENTIAL")
    minio_endpoint = os.getenv("MINIO_ENDPOINT", "http://localhost:9012")

    if not polaris_uri or not credential:
        pytest.skip(
            "POLARIS_CATALOG_URI / POLARIS_CREDENTIAL not set – skipping Polaris tests"
        )

    async_verifier = PolarisVerifier(
        polaris_uri=polaris_uri,
        credential=credential,
        minio_endpoint=minio_endpoint,
    )
    return SyncPolarisVerifier(async_verifier)
