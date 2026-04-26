import json
import logging
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote

import aiohttp

from service.exceptions import PolarisOperationError

logger = logging.getLogger(__name__)

NAMESPACE_READ_PRIVILEGES = (
    "NAMESPACE_LIST",
    "NAMESPACE_READ_PROPERTIES",
    "TABLE_LIST",
    "TABLE_READ_PROPERTIES",
    "TABLE_READ_DATA",
)
NAMESPACE_WRITE_PRIVILEGES = (
    *NAMESPACE_READ_PRIVILEGES,
    "NAMESPACE_WRITE_PROPERTIES",
    "TABLE_WRITE_PROPERTIES",
    "TABLE_WRITE_DATA",
)


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
            self.catalog_base_url = base_uri.replace("/api/catalog", "/api/catalog/v1")
            self.oauth_url = base_uri.replace(
                "/api/catalog", "/api/catalog/v1/oauth/tokens"
            )
        else:
            self.base_url = f"{base_uri}/api/management/v1"
            self.catalog_base_url = f"{base_uri}/api/catalog/v1"
            self.oauth_url = f"{base_uri}/api/catalog/v1/oauth/tokens"

        parts = root_credential.split(":", 1)
        self.client_id = parts[0]
        self.client_secret = parts[1] if len(parts) > 1 else ""
        self.minio_endpoint = minio_endpoint
        self._token: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create a shared aiohttp.ClientSession for connection reuse."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the shared aiohttp session. Call during application shutdown."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

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
        self, method: str, endpoint: str, base_url: str | None = None, **kwargs: Any
    ) -> Dict[str, Any]:
        """Make an authenticated request to Polaris management API."""
        session = await self._get_session()
        token = await self._get_token(session)

        headers: dict[str, str] = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        headers["Polaris-Realm"] = "POLARIS"
        headers["Accept"] = "application/json"

        url = f"{base_url or self.base_url}/{endpoint.lstrip('/')}"

        try:
            async with session.request(method, url, headers=headers, **kwargs) as resp:
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
            raise PolarisOperationError(str(e.message), status=e.status) from e

    async def _catalog_request(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """Make an authenticated request to the Polaris Iceberg catalog API."""
        return await self._request(
            method,
            endpoint,
            base_url=self.catalog_base_url,
            **kwargs,
        )

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
        except PolarisOperationError as e:
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
        except PolarisOperationError as e:
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
        except PolarisOperationError as e:
            if e.status == 409:
                return await self._request(
                    "GET", f"/catalogs/{catalog}/catalog-roles/{role_name}"
                )
            raise e

    async def list_catalog_roles(self, catalog: str) -> List[Dict[str, Any]]:
        """List all roles defined within a catalog."""
        resp = await self._request("GET", f"/catalogs/{catalog}/catalog-roles")
        return resp.get("roles", [])

    async def delete_catalog_role(self, catalog: str, role_name: str) -> None:
        """Delete a role from a catalog."""
        try:
            await self._request(
                "DELETE",
                f"/catalogs/{catalog}/catalog-roles/{role_name}",
            )
            logger.info("Deleted catalog role %s from catalog %s", role_name, catalog)
        except PolarisOperationError as e:
            if e.status == 404:
                logger.info(
                    "Catalog role %s not found in catalog %s, ignoring deletion.",
                    role_name,
                    catalog,
                )
            else:
                raise

    async def get_grants_for_catalog_role(
        self, catalog: str, role_name: str
    ) -> List[str]:
        """List catalog-scoped privilege names already granted to a catalog role."""
        grants = await self.list_grants_for_catalog_role(catalog, role_name)
        return [
            grant.get("privilege", "")
            for grant in grants
            if grant.get("privilege") and grant.get("type", "catalog") == "catalog"
        ]

    async def list_grants_for_catalog_role(
        self, catalog: str, role_name: str
    ) -> List[Dict[str, Any]]:
        """List full grant resources already assigned to a catalog role."""
        resp = await self._request(
            "GET", f"/catalogs/{catalog}/catalog-roles/{role_name}/grants"
        )
        return [_unwrap_grant_resource(grant) for grant in resp.get("grants", [])]

    async def grant_catalog_privilege(
        self, catalog: str, role_name: str, privilege: str = "CATALOG_MANAGE_CONTENT"
    ) -> Dict[str, Any]:
        """Grant a privilege on the catalog to a catalog role (idempotent — checks first)."""
        existing = await self.get_grants_for_catalog_role(catalog, role_name)
        if privilege in existing:
            logger.info(
                "Privilege '%s' already granted to role '%s' on catalog '%s', skipping.",
                privilege,
                role_name,
                catalog,
            )
            return {}

        payload = {"grant": {"type": "catalog", "privilege": privilege}}
        return await self._request(
            "PUT",
            f"/catalogs/{catalog}/catalog-roles/{role_name}/grants",
            json=payload,
        )

    async def grant_namespace_privilege(
        self,
        catalog: str,
        role_name: str,
        namespace: Sequence[str],
        privilege: str,
    ) -> Dict[str, Any]:
        """Grant a namespace-scoped privilege to a catalog role."""
        namespace_parts = _normalize_namespace(namespace)
        existing = await self.list_grants_for_catalog_role(catalog, role_name)
        if _has_namespace_grant(existing, namespace_parts, privilege):
            logger.info(
                "Namespace privilege '%s' already granted to role '%s' on %s/%s, skipping.",
                privilege,
                role_name,
                catalog,
                ".".join(namespace_parts),
            )
            return {}

        payload = {
            "grant": {
                "type": "namespace",
                "namespace": list(namespace_parts),
                "privilege": privilege,
            }
        }
        return await self._request(
            "PUT",
            f"/catalogs/{catalog}/catalog-roles/{role_name}/grants",
            json=payload,
        )

    async def revoke_namespace_privilege(
        self,
        catalog: str,
        role_name: str,
        namespace: Sequence[str],
        privilege: str,
    ) -> Dict[str, Any]:
        """Revoke a namespace-scoped privilege from a catalog role."""
        namespace_parts = _normalize_namespace(namespace)
        existing = await self.list_grants_for_catalog_role(catalog, role_name)
        if not _has_namespace_grant(existing, namespace_parts, privilege):
            logger.info(
                "Namespace privilege '%s' is not granted to role '%s' on %s/%s, skipping revoke.",
                privilege,
                role_name,
                catalog,
                ".".join(namespace_parts),
            )
            return {}

        payload = {
            "grant": {
                "type": "namespace",
                "namespace": list(namespace_parts),
                "privilege": privilege,
            }
        }
        return await self._request(
            "DELETE",
            f"/catalogs/{catalog}/catalog-roles/{role_name}/grants",
            json=payload,
        )

    async def ensure_namespace_acl_role_bindings(
        self,
        catalog: str,
        catalog_role: str,
        principal_role: str,
        namespace: Sequence[str],
        access_level: str,
    ) -> None:
        """Ensure Polaris roles and grants for one namespace ACL role record."""
        namespace_parts = _normalize_namespace(namespace)
        await self.create_catalog_role(catalog, catalog_role)
        for privilege in namespace_privileges_for_access_level(access_level):
            await self.grant_namespace_privilege(
                catalog,
                catalog_role,
                namespace_parts,
                privilege,
            )
        await self.create_principal_role(principal_role)
        await self.grant_catalog_role_to_principal_role(
            catalog,
            catalog_role,
            principal_role,
        )

    async def revoke_namespace_acl_role_privileges(
        self,
        catalog: str,
        catalog_role: str,
        namespace: Sequence[str],
        access_level: str,
    ) -> None:
        """Revoke all namespace-scoped privileges for an ACL role."""
        namespace_parts = _normalize_namespace(namespace)
        for privilege in namespace_privileges_for_access_level(access_level):
            await self.revoke_namespace_privilege(
                catalog,
                catalog_role,
                namespace_parts,
                privilege,
            )

    async def create_principal_role(self, role_name: str) -> Dict[str, Any]:
        """Create a principal role."""
        payload = {"principalRole": {"name": role_name, "properties": {}}}
        try:
            return await self._request("POST", "/principal-roles", json=payload)
        except PolarisOperationError as e:
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
        except PolarisOperationError as e:
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
            await self.grant_catalog_privilege(tenant_name, reader_role_name, privilege)

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
        except PolarisOperationError as e:
            if e.status == 404:
                logger.info(f"Polaris principal {name} not found, ignoring deletion.")
            else:
                logger.warning(f"Failed to delete Polaris principal {name}: {e}")

    async def delete_catalog(self, name: str) -> None:
        """Delete a Polaris catalog."""
        try:
            await self._request("DELETE", f"/catalogs/{name}")
            logger.info(f"Deleted Polaris catalog {name}")
        except PolarisOperationError as e:
            if e.status == 404:
                logger.info(f"Polaris catalog {name} not found, ignoring deletion.")
            else:
                logger.warning(f"Failed to delete Polaris catalog {name}: {e}")

    async def delete_namespace(
        self,
        catalog: str,
        namespace: Sequence[str],
    ) -> None:
        """Delete an empty namespace from a catalog."""
        namespace_path = _namespace_url(_normalize_namespace(namespace))
        try:
            await self._catalog_request(
                "DELETE",
                f"/{catalog}/namespaces/{namespace_path}",
            )
            logger.info(
                "Deleted namespace %s from catalog %s",
                ".".join(namespace),
                catalog,
            )
        except PolarisOperationError as e:
            if e.status == 404:
                logger.info(
                    "Namespace %s not found in catalog %s, ignoring deletion.",
                    ".".join(namespace),
                    catalog,
                )
            else:
                raise

    async def delete_all_namespaces(self, catalog: str) -> None:
        """Best-effort delete all empty namespaces in a catalog, deepest first."""
        try:
            namespaces = await self._list_all_namespaces(catalog)
        except PolarisOperationError as e:
            if e.status == 404:
                return
            raise

        for namespace in sorted(namespaces, key=len, reverse=True):
            try:
                await self.delete_namespace(catalog, namespace)
            except PolarisOperationError as e:
                logger.warning(
                    "Failed to delete namespace %s from catalog %s: %s",
                    ".".join(namespace),
                    catalog,
                    e,
                )

    async def _list_all_namespaces(self, catalog: str) -> list[tuple[str, ...]]:
        """Return all namespaces in a catalog, including nested namespaces."""
        discovered: list[tuple[str, ...]] = []
        pending = list(await self.list_namespaces(catalog))
        while pending:
            namespace = pending.pop()
            discovered.append(namespace)
            pending.extend(await self.list_namespaces(catalog, parent=namespace))
        return discovered

    async def delete_all_catalog_roles(self, catalog: str) -> None:
        """Best-effort delete all catalog roles before dropping a catalog."""
        try:
            roles = await self.list_catalog_roles(catalog)
        except PolarisOperationError as e:
            if e.status == 404:
                return
            raise

        for role in roles:
            role_name = role.get("name")
            if not role_name:
                continue
            try:
                await self.delete_catalog_role(catalog, role_name)
            except PolarisOperationError as e:
                logger.warning(
                    "Failed to delete catalog role %s from catalog %s: %s",
                    role_name,
                    catalog,
                    e,
                )

    async def delete_principal_role(self, name: str) -> None:
        """Delete a Polaris principal role."""
        try:
            await self._request("DELETE", f"/principal-roles/{name}")
            logger.info(f"Deleted Polaris principal role {name}")
        except PolarisOperationError as e:
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

        # Remove top-level principal roles before catalog roles so any
        # principal-role -> catalog-role bindings are gone before the catalog
        # role deletion pass.
        await self.delete_principal_role(writer_principal_role)
        await self.delete_principal_role(reader_principal_role)

        # Delete empty namespaces first; Polaris refuses to drop non-empty catalogs.
        await self.delete_all_namespaces(tenant_name)

        # Delete catalog roles explicitly; Polaris will not drop a catalog while
        # catalog roles such as catalog_admin, tenant readers/writers, or
        # namespace ACL roles remain.
        await self.delete_all_catalog_roles(tenant_name)

        # Delete the catalog after child resources are gone.
        await self.delete_catalog(tenant_name)

    async def namespace_exists(self, catalog: str, namespace: Sequence[str]) -> bool:
        """Return whether a namespace exists in the Iceberg REST catalog API."""
        namespace_path = _namespace_url(_normalize_namespace(namespace))
        try:
            await self._catalog_request(
                "GET", f"/{catalog}/namespaces/{namespace_path}"
            )
            return True
        except PolarisOperationError as e:
            if e.status == 404:
                return False
            raise

    async def list_namespaces(
        self,
        catalog: str,
        parent: Sequence[str] | None = None,
    ) -> List[tuple[str, ...]]:
        """List child namespaces in a catalog or under a parent namespace."""
        params = None
        if parent is not None:
            params = {"parent": _namespace_query_value(_normalize_namespace(parent))}
        resp = await self._catalog_request(
            "GET",
            f"/{catalog}/namespaces",
            params=params,
        )
        namespaces = resp.get("namespaces", [])
        if not isinstance(namespaces, list):
            return []
        return [
            namespace
            for item in namespaces
            if (namespace := _namespace_from_payload_item(item))
        ]

    async def list_tables_in_namespace(
        self, catalog: str, namespace: Sequence[str]
    ) -> List[str]:
        """List table names inside a namespace via the Iceberg REST catalog API."""
        namespace_path = _namespace_url(_normalize_namespace(namespace))
        resp = await self._catalog_request(
            "GET", f"/{catalog}/namespaces/{namespace_path}/tables"
        )
        identifiers = resp.get("identifiers")
        if isinstance(identifiers, list):
            return [
                item["name"]
                for item in identifiers
                if isinstance(item, dict) and item.get("name")
            ]
        tables = resp.get("tables", [])
        return [
            item["name"] if isinstance(item, dict) else str(item)
            for item in tables
            if item
        ]

    async def load_table(
        self,
        catalog: str,
        namespace: Sequence[str],
        table_name: str,
    ) -> Dict[str, Any]:
        """Load table metadata from the Iceberg REST catalog API."""
        namespace_path = _namespace_url(_normalize_namespace(namespace))
        table_path = quote(table_name, safe="")
        return await self._catalog_request(
            "GET",
            f"/{catalog}/namespaces/{namespace_path}/tables/{table_path}",
        )


def namespace_privileges_for_access_level(access_level: str) -> tuple[str, ...]:
    """Return the Polaris namespace privilege set for a read or write grant."""
    normalized = access_level.strip().lower()
    if normalized == "read":
        return NAMESPACE_READ_PRIVILEGES
    if normalized == "write":
        return NAMESPACE_WRITE_PRIVILEGES
    raise ValueError("access_level must be 'read' or 'write'")


def _normalize_namespace(namespace: Sequence[str]) -> tuple[str, ...]:
    if isinstance(namespace, str):
        raise ValueError("namespace must be a sequence, not a dotted string")
    namespace_parts = tuple(part.strip() for part in namespace)
    if not namespace_parts:
        raise ValueError("namespace must not be empty")
    if any(not part for part in namespace_parts):
        raise ValueError("namespace must not contain empty values")
    return namespace_parts


def _namespace_url(namespace: Sequence[str]) -> str:
    return "%1F".join(quote(part, safe="") for part in namespace)


def _namespace_query_value(namespace: Sequence[str]) -> str:
    return "\x1f".join(namespace)


def _namespace_from_payload_item(item: Any) -> tuple[str, ...] | None:
    if isinstance(item, list):
        return tuple(str(part) for part in item if part)
    if isinstance(item, str):
        return tuple(part for part in item.split(".") if part)
    if isinstance(item, dict):
        namespace = item.get("namespace")
        if isinstance(namespace, list):
            return tuple(str(part) for part in namespace if part)
        name = item.get("name")
        if isinstance(name, str):
            return tuple(part for part in name.split(".") if part)
    return None


def _unwrap_grant_resource(grant: Dict[str, Any]) -> Dict[str, Any]:
    nested = grant.get("grant")
    if isinstance(nested, dict):
        return nested
    return grant


def _has_namespace_grant(
    grants: Sequence[Dict[str, Any]],
    namespace: Sequence[str],
    privilege: str,
) -> bool:
    namespace_parts = list(namespace)
    return any(
        grant.get("type") == "namespace"
        and grant.get("namespace") == namespace_parts
        and grant.get("privilege") == privilege
        for grant in grants
    )
