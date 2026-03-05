import json
import logging
from typing import Any, Dict, List, Optional
import aiohttp

logger = logging.getLogger(__name__)


class PolarisService:
    """Service to interact with Apache Polaris management REST API."""

    def __init__(
        self,
        polaris_uri: str,
        root_credential: str,
        minio_endpoint: str | None = None,
    ):
        """
        Initialize the Polaris service.

        Args:
            polaris_uri: The base URI for Polaris API (e.g., http://polaris:8181/api/management/v1)
            root_credential: The client_id:client_secret string for Polaris admin access
            minio_endpoint: MinIO S3 endpoint URL (e.g., http://minio:9002). Required for
                creating catalogs with correct storageConfigInfo for MinIO connectivity.
        """
        # Strip trailing slashes and /api/catalog if provided by mistake
        base_uri = polaris_uri.rstrip("/")
        if base_uri.endswith("/api/catalog"):
            self.base_url = base_uri.replace("/api/catalog", "/api/management/v1")
            self.oauth_url = base_uri.replace(
                "/api/catalog", "/api/catalog/v1/oauth/tokens"
            )
        else:
            self.base_url = f"{base_uri}/api/management/v1"
            self.oauth_url = f"{base_uri}/api/catalog/v1/oauth/tokens"

        parts = root_credential.split(":", 1)
        self.client_id = parts[0]
        self.client_secret = parts[1] if len(parts) > 1 else ""
        self.minio_endpoint = minio_endpoint
        self._token: Optional[str] = None

    async def _get_token(self, session: aiohttp.ClientSession) -> str:
        """Get or refresh OAuth token for Polaris admin access."""
        if self._token is not None:
            return self._token

        data = {"grant_type": "client_credentials", "scope": "PRINCIPAL_ROLE:ALL"}
        auth = aiohttp.BasicAuth(self.client_id, self.client_secret)
        headers = {"Polaris-Realm": "POLARIS"}

        async with session.post(
            self.oauth_url, data=data, auth=auth, headers=headers
        ) as resp:
            resp.raise_for_status()
            result = await resp.json()
            self._token = result["access_token"]
            return str(self._token)

    async def _request(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """Make an authenticated request to Polaris management API."""
        async with aiohttp.ClientSession() as session:
            token = await self._get_token(session)

            headers: dict[str, str] = kwargs.pop("headers", {})
            headers["Authorization"] = f"Bearer {token}"
            headers["Polaris-Realm"] = "POLARIS"
            headers["Accept"] = "application/json"

            url = f"{self.base_url}/{endpoint.lstrip('/')}"

            try:
                async with session.request(
                    method, url, headers=headers, **kwargs
                ) as resp:
                    if resp.status >= 400:
                        body_text = await resp.text()
                        error_message: str = resp.reason or "Unknown Error"
                        if body_text:
                            # Try to extract the inner error message from Polaris JSON
                            try:
                                error_json = json.loads(body_text)
                                if (
                                    "error" in error_json
                                    and "message" in error_json["error"]
                                ):
                                    error_message = str(error_json["error"]["message"])
                                else:
                                    error_message = body_text
                            except (json.JSONDecodeError, TypeError):
                                error_message = body_text

                        raise aiohttp.ClientResponseError(
                            resp.request_info,
                            resp.history,
                            status=resp.status,
                            message=error_message,
                            headers=resp.headers,
                        )

                    # Some endpoints return 201/204 with no JSON body
                    if resp.status == 204:
                        return {}
                    content_type = resp.headers.get("Content-Type", "")
                    if resp.status == 201 and "application/json" not in content_type:
                        return {}
                    return await resp.json()
            except aiohttp.ClientResponseError as e:
                # If we get 401, token might have expired. Clear it so next request fetches a new one.
                if e.status == 401:
                    self._token = None
                    logger.warning(
                        "Polaris admin token expired or invalid, clearing cache."
                    )
                raise e

    async def create_catalog(
        self,
        name: str,
        storage_location: str,
        s3_endpoint: str | None = None,
    ) -> Dict[str, Any]:
        """Create a Polaris catalog with S3/MinIO storage.

        Args:
            name: Catalog name (e.g., "user_tgu2", "tenant_globalusers")
            storage_location: S3 base path (e.g., "s3a://cdm-lake/users-general-warehouse/tgu2/iceberg/")
            s3_endpoint: S3/MinIO endpoint URL. When provided, storageConfigInfo includes
                endpoint, pathStyleAccess, and stsUnavailable fields required for MinIO.
                Falls back to self.minio_endpoint if not provided.
        """
        endpoint = s3_endpoint or self.minio_endpoint

        # Build storageConfigInfo — fields MUST be at the top level (flat schema).
        # Polaris silently ignores fields nested under "s3".
        storage_config: Dict[str, Any] = {
            "storageType": "S3",
            "allowedLocations": [storage_location],
        }
        if endpoint:
            storage_config.update(
                {
                    "endpoint": endpoint,
                    "endpointInternal": endpoint,
                    "pathStyleAccess": True,
                    "stsUnavailable": True,
                    "region": "us-east-1",
                }
            )

        payload = {
            "catalog": {
                "name": name,
                "type": "INTERNAL",
                "properties": {"default-base-location": storage_location},
                "storageConfigInfo": storage_config,
            }
        }
        try:
            return await self._request("POST", "/catalogs", json=payload)
        except aiohttp.ClientResponseError as e:
            if e.status == 409:  # Conflict - already exists
                return await self.get_catalog(name)
            raise e

    async def get_catalog(self, name: str) -> Dict[str, Any]:
        """Get a specific catalog."""
        return await self._request("GET", f"/catalogs/{name}")

    async def list_catalogs(self) -> List[Dict[str, Any]]:
        """List all catalogs."""
        resp = await self._request("GET", "/catalogs")
        return resp.get("catalogs", [])

    async def create_principal(self, name: str) -> Dict[str, Any]:
        """Create a Polaris principal and its credentials."""
        payload = {"principal": {"name": name, "type": "USER", "properties": {}}}
        try:
            return await self._request("POST", "/principals", json=payload)
        except aiohttp.ClientResponseError as e:
            if e.status == 409:
                return await self.get_principal(name)
            raise e

    async def get_principal(self, name: str) -> Dict[str, Any]:
        """Get a specific principal."""
        return await self._request("GET", f"/principals/{name}")

    async def get_principal_role(self, role_name: str) -> Dict[str, Any]:
        """Get a specific principal role by name."""
        return await self._request("GET", f"/principal-roles/{role_name}")

    async def get_principal_roles_for_principal(self, principal: str) -> List[str]:
        """List all principal role names assigned to a given principal."""
        resp = await self._request("GET", f"/principals/{principal}/principal-roles")
        roles = resp.get("roles", [])
        return [r.get("name", "") for r in roles if r.get("name")]

    async def list_principal_roles(self) -> List[Dict[str, Any]]:
        """List all principal roles in Polaris."""
        resp = await self._request("GET", "/principal-roles")
        return resp.get("roles", [])

    async def reset_principal_credentials(self, name: str) -> Dict[str, Any]:
        """Reset credentials for a principal (admin operation).

        Uses POST /principals/{name}/reset which is allowed for admin principals.
        The rotate endpoint (POST /principals/{name}/rotate) can only be called
        by the principal itself, not by an admin on behalf of another principal.

        Returns PrincipalWithCredentials with clientId and clientSecret.
        """
        return await self._request("POST", f"/principals/{name}/reset", json={})

    # Alias for backwards compatibility
    rotate_principal_credentials = reset_principal_credentials

    async def create_catalog_role(self, catalog: str, role_name: str) -> Dict[str, Any]:
        """Create a role within a catalog."""
        payload = {"catalogRole": {"name": role_name, "properties": {}}}
        try:
            return await self._request(
                "POST", f"/catalogs/{catalog}/catalog-roles", json=payload
            )
        except aiohttp.ClientResponseError as e:
            if e.status == 409:
                return await self._request(
                    "GET", f"/catalogs/{catalog}/catalog-roles/{role_name}"
                )
            raise e

    async def grant_catalog_privilege(
        self, catalog: str, role_name: str, privilege: str = "CATALOG_MANAGE_CONTENT"
    ) -> Dict[str, Any]:
        """Grant a privilege on the catalog to a catalog role."""
        payload = {"grant": {"type": "catalog", "privilege": privilege}}
        try:
            return await self._request(
                "PUT",
                f"/catalogs/{catalog}/catalog-roles/{role_name}/grants",
                json=payload,
            )
        except aiohttp.ClientResponseError as e:
            if e.status == 409 or (
                e.status == 500 and "already exists" in str(e.message)
            ):
                logger.warning(
                    "Conflict while granting catalog privilege '%s' on catalog "
                    "'%s' to role '%s'; assuming privilege is already granted.",
                    privilege,
                    catalog,
                    role_name,
                )
                return {}
            logger.warning(
                "Failed to grant catalog privilege '%s' on catalog '%s' to role '%s': %s",
                privilege,
                catalog,
                role_name,
                e,
            )
            raise

    async def create_principal_role(self, role_name: str) -> Dict[str, Any]:
        """Create a principal role."""
        payload = {"principalRole": {"name": role_name, "properties": {}}}
        try:
            return await self._request("POST", "/principal-roles", json=payload)
        except aiohttp.ClientResponseError as e:
            if e.status == 409:
                return await self._request("GET", f"/principal-roles/{role_name}")
            raise e

    async def get_catalog_roles_for_principal_role(
        self, principal_role: str, catalog: str
    ) -> List[str]:
        """List catalog role names granted to a principal role for a specific catalog."""
        resp = await self._request(
            "GET", f"/principal-roles/{principal_role}/catalog-roles/{catalog}"
        )
        roles = resp.get("roles", [])
        return [r.get("name", "") for r in roles if r.get("name")]

    async def grant_catalog_role_to_principal_role(
        self, catalog: str, catalog_role: str, principal_role: str
    ) -> Dict[str, Any]:
        """Grant a catalog role to a principal role (idempotent — checks first)."""
        # Check if already granted to avoid Polaris duplicate key errors
        existing = await self.get_catalog_roles_for_principal_role(
            principal_role, catalog
        )
        if catalog_role in existing:
            logger.info(
                "Catalog role '%s' already granted to principal role '%s' on catalog '%s', skipping.",
                catalog_role,
                principal_role,
                catalog,
            )
            return {}

        payload = {"catalogRole": {"name": catalog_role}}
        return await self._request(
            "PUT",
            f"/principal-roles/{principal_role}/catalog-roles/{catalog}",
            json=payload,
        )

    async def grant_principal_role_to_principal(
        self, principal: str, principal_role: str
    ) -> Dict[str, Any]:
        """Assign a principal role to a user (principal) (idempotent — checks first)."""
        existing = await self.get_principal_roles_for_principal(principal)
        if principal_role in existing:
            logger.info(
                "Principal role '%s' already assigned to principal '%s', skipping.",
                principal_role,
                principal,
            )
            return {}

        payload = {"principalRole": {"name": principal_role}}
        return await self._request(
            "PUT", f"/principals/{principal}/principal-roles", json=payload
        )

    async def revoke_principal_role_from_principal(
        self, principal: str, principal_role: str
    ) -> Dict[str, Any]:
        """Revoke a principal role from a user (principal) (idempotent — checks first)."""
        try:
            existing = await self.get_principal_roles_for_principal(principal)
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                logger.info(
                    "Principal '%s' not found in Polaris, skipping revoke of '%s'.",
                    principal,
                    principal_role,
                )
                return {}
            raise

        if principal_role not in existing:
            logger.info(
                "Principal role '%s' not assigned to principal '%s', skipping revoke.",
                principal_role,
                principal,
            )
            return {}

        return await self._request(
            "DELETE", f"/principals/{principal}/principal-roles/{principal_role}"
        )

    async def ensure_tenant_catalog(
        self,
        group_name: str,
        storage_location: str,
    ) -> None:
        """Ensure a Polaris tenant catalog exists with writer/reader roles.

        Idempotent — safe to call on every user provisioning. All create
        operations handle 409 (already exists) gracefully.

        Args:
            group_name: The MinIO group name (e.g., "globalusers")
            storage_location: S3 storage path for the catalog
        """
        tenant_name = f"tenant_{group_name}"

        # Create catalog (idempotent)
        await self.create_catalog(tenant_name, storage_location)

        # Writer role: CATALOG_MANAGE_CONTENT
        writer_role_name = f"{group_name}_writer"
        await self.create_catalog_role(tenant_name, writer_role_name)
        await self.grant_catalog_privilege(
            tenant_name, writer_role_name, "CATALOG_MANAGE_CONTENT"
        )

        writer_principal_role = f"{group_name}_member"
        await self.create_principal_role(writer_principal_role)
        await self.grant_catalog_role_to_principal_role(
            tenant_name, writer_role_name, writer_principal_role
        )

        # Reader role: read data + list namespaces/tables (but no create/write/drop)
        reader_role_name = f"{group_name}_reader"
        await self.create_catalog_role(tenant_name, reader_role_name)
        for privilege in ["TABLE_READ_DATA", "TABLE_LIST", "NAMESPACE_LIST"]:
            try:
                await self.grant_catalog_privilege(
                    tenant_name, reader_role_name, privilege
                )
            except Exception:
                pass  # Some privileges may not apply at catalog level in all Polaris versions

        reader_principal_role = f"{group_name}ro_member"
        await self.create_principal_role(reader_principal_role)
        await self.grant_catalog_role_to_principal_role(
            tenant_name, reader_role_name, reader_principal_role
        )

    async def delete_principal(self, name: str) -> None:
        """Delete a Polaris principal."""
        try:
            await self._request("DELETE", f"/principals/{name}")
            logger.info(f"Deleted Polaris principal {name}")
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                logger.info(f"Polaris principal {name} not found, ignoring deletion.")
            else:
                logger.warning(f"Failed to delete Polaris principal {name}: {e}")

    async def delete_catalog(self, name: str) -> None:
        """Delete a Polaris catalog."""
        try:
            await self._request("DELETE", f"/catalogs/{name}")
            logger.info(f"Deleted Polaris catalog {name}")
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                logger.info(f"Polaris catalog {name} not found, ignoring deletion.")
            else:
                logger.warning(f"Failed to delete Polaris catalog {name}: {e}")

    async def delete_principal_role(self, name: str) -> None:
        """Delete a Polaris principal role."""
        try:
            await self._request("DELETE", f"/principal-roles/{name}")
            logger.info(f"Deleted Polaris principal role {name}")
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                logger.info(
                    f"Polaris principal role {name} not found, ignoring deletion."
                )
            else:
                logger.warning(f"Failed to delete Polaris principal role {name}: {e}")

    async def drop_tenant_catalog(self, group_name: str) -> None:
        """Drop a Polaris tenant catalog and its associated principal roles.

        Args:
            group_name: The MinIO group name corresponding to the catalog
        """
        # Roles and catalogs that were created in `ensure_tenant_catalog`
        tenant_name = f"tenant_{group_name}"
        writer_principal_role = f"{group_name}_member"
        reader_principal_role = f"{group_name}ro_member"

        # Delete the catalog (this drops catalog-roles and their grants internally in Polaris)
        await self.delete_catalog(tenant_name)

        # Delete the top-level principal roles bound to users
        await self.delete_principal_role(writer_principal_role)
        await self.delete_principal_role(reader_principal_role)
