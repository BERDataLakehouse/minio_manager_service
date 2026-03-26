"""Pydantic models for tenant metadata, stewards, and member profiles."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

# Validates http(s) scheme and structure, stored as str for DB/JSON compatibility.
HttpUrlStr = Annotated[str, Field(max_length=2048)]


def _validate_http_url(v: str | None) -> str | None:
    """Reject non-http(s) schemes (e.g. javascript:) to prevent XSS downstream."""
    if v is not None:
        HttpUrl(v)  # raises ValidationError on bad scheme/structure
    return v


# --- Request Models ---


class TenantMetadataUpdate(BaseModel):
    """Partial update for tenant metadata."""

    model_config = ConfigDict(str_strip_whitespace=True)

    display_name: str | None = None
    description: str | None = None
    website: HttpUrlStr | None = None  # URL for the tenant's website or project page
    organization: str | None = None  # User-supplied; not available from KBase Auth

    @field_validator("website")
    @classmethod
    def website_must_be_http(cls, v: str | None) -> str | None:
        return _validate_http_url(v)


class StewardAssignment(BaseModel):
    """Request body for assigning a steward."""

    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=1)


# --- Response Models ---


class UserProfile(BaseModel):
    """User profile with details from KBase Auth."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: str
    display_name: str | None = None
    email: str | None = None


class TenantMetadataResponse(BaseModel):
    """Full tenant metadata for the detail page."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    tenant_name: str
    display_name: str | None = None
    description: str | None = None
    website: str | None = None
    organization: str | None = None
    created_by: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None


class TenantStewardResponse(BaseModel):
    """Steward with profile details."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: str
    display_name: str | None = None
    email: str | None = None
    assigned_by: str
    assigned_at: datetime


class TenantMemberResponse(BaseModel):
    """Member with profile details and access level."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: str
    display_name: str | None = None
    email: str | None = None
    access_level: Literal["read_write", "read_only"]
    is_steward: bool


class TenantStoragePaths(BaseModel):
    """Storage paths associated with the tenant."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    general_warehouse: str
    sql_warehouse: str
    namespace_prefix: str


class TenantDetailResponse(BaseModel):
    """Complete tenant detail — everything the frontend needs."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    metadata: TenantMetadataResponse
    stewards: list[TenantStewardResponse]
    members: list[TenantMemberResponse]
    member_count: int
    storage_paths: TenantStoragePaths


class TenantSummaryResponse(BaseModel):
    """Lightweight tenant listing for directory/search."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    tenant_name: str
    display_name: str | None = None
    description: str | None = None
    website: str | None = None
    member_count: int
    is_member: bool
    is_steward: bool
