"""Pydantic models for Polaris namespace ACL APIs."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from polaris.namespace_acl_store import (
    NamespaceAclGrantRecord,
    normalize_namespace_parts,
)

NamespaceAccessLevel = Literal["read", "write"]
NamespaceGrantStatus = Literal["pending", "active", "shadowed", "sync_error", "revoked"]


class NamespaceAclGrantRequest(BaseModel):
    """Request to grant namespace access to a user."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    username: Annotated[str, Field(min_length=1, description="KBase username")]
    namespace: Annotated[
        list[str],
        Field(min_length=1, description="Namespace name parts, not a dotted string"),
    ]
    access_level: Annotated[
        NamespaceAccessLevel,
        Field(description="Namespace access level"),
    ] = "read"

    @field_validator("namespace")
    @classmethod
    def validate_namespace(cls, value: list[str]) -> list[str]:
        """Reject empty namespace parts."""
        return list(normalize_namespace_parts(value))


class NamespaceAclRevokeRequest(BaseModel):
    """Request to revoke namespace access from a user."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    username: Annotated[str, Field(min_length=1, description="KBase username")]
    namespace: Annotated[
        list[str],
        Field(min_length=1, description="Namespace name parts, not a dotted string"),
    ]

    @field_validator("namespace")
    @classmethod
    def validate_namespace(cls, value: list[str]) -> list[str]:
        """Reject empty namespace parts."""
        return list(normalize_namespace_parts(value))


class NamespaceAclGrantResponse(BaseModel):
    """Namespace ACL grant response."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    id: str
    tenant_name: str
    namespace: list[str]
    namespace_name: str
    username: str
    access_level: NamespaceAccessLevel
    status: NamespaceGrantStatus
    granted_by: str
    granted_at: datetime
    updated_by: str
    updated_at: datetime
    revoked_by: str | None = None
    revoked_at: datetime | None = None
    last_synced_at: datetime | None = None
    last_sync_error: str | None = None

    @classmethod
    def from_record(
        cls,
        grant: NamespaceAclGrantRecord,
    ) -> "NamespaceAclGrantResponse":
        """Build response from store record."""
        return cls(
            id=grant.id,
            tenant_name=grant.tenant_name,
            namespace=list(grant.namespace_parts),
            namespace_name=grant.namespace_name,
            username=grant.username,
            access_level=grant.access_level,
            status=grant.status,
            granted_by=grant.granted_by,
            granted_at=grant.granted_at,
            updated_by=grant.updated_by,
            updated_at=grant.updated_at,
            revoked_by=grant.revoked_by,
            revoked_at=grant.revoked_at,
            last_synced_at=grant.last_synced_at,
            last_sync_error=grant.last_sync_error,
        )


class NamespaceAclSyncResponse(BaseModel):
    """Admin namespace ACL reconciliation response."""

    model_config = ConfigDict(frozen=True)

    username: str
    policy_name: str
    synced_grants: list[str]
    failed_grants: list[dict[str, str]]
    revoked_stale_roles: list[str]
    policy_size_bytes: int


class NamespaceAclBulkSyncResponse(BaseModel):
    """Admin namespace ACL reconciliation response for a tenant or all users."""

    model_config = ConfigDict(frozen=True)

    scope: Literal["all", "tenant"]
    tenant_name: str | None = None
    reconciled_users: list[str]
    results: list[NamespaceAclSyncResponse]


class EffectiveAccessGroupTenant(BaseModel):
    """Tenant catalog access inherited from MinIO tenant membership."""

    model_config = ConfigDict(frozen=True)

    tenant_name: str
    catalog_name: str
    access_level: Literal["read_only", "read_write"]


class EffectiveAccessNamespaceGrant(BaseModel):
    """Namespace grant visible to a user through namespace ACLs."""

    model_config = ConfigDict(frozen=True)

    grant_id: str
    namespace: list[str]
    namespace_name: str
    access_level: NamespaceAccessLevel


class EffectiveAccessNamespaceTenant(BaseModel):
    """Tenant catalog access inherited from active namespace ACL grants."""

    model_config = ConfigDict(frozen=True)

    tenant_name: str
    catalog_name: str
    namespaces: list[EffectiveAccessNamespaceGrant]


class PolarisEffectiveAccessResponse(BaseModel):
    """Effective Polaris access for one user."""

    model_config = ConfigDict(frozen=True)

    username: str
    personal_catalog: str
    group_tenants: list[EffectiveAccessGroupTenant]
    namespace_acl_tenants: list[EffectiveAccessNamespaceTenant]
