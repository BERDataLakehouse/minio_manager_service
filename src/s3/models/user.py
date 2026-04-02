"""User-related Pydantic models for the MinIO Manager Service."""

from typing import Annotated, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..utils.validators import validate_username
from .policy import PolicyModel


class BaseUserModel(BaseModel):
    """
    Base user model with core user information.
    All other user models should inherit from this.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )

    username: Annotated[
        str,
        Field(
            min_length=2,
            max_length=64,
            description="Unique username identifier",
            examples=["john.doe", "admin", "data_scientist_01"],
        ),
    ]
    access_key: Annotated[
        str, Field(description="MinIO access key for API authentication")
    ]
    secret_key: Annotated[
        Optional[str],
        Field(
            default=None,
            description="MinIO secret key (only returned during creation/rotation for security)",
        ),
    ] = None

    @field_validator("username")
    @classmethod
    def validate_username_format(cls, v: str) -> str:
        """Validate username using centralized validator."""
        return validate_username(v)


class UserModel(BaseUserModel):
    """
    Enhanced user model with comprehensive policy and group information.
    Includes full policy details and aggregated information.
    """

    home_paths: Annotated[
        List[str],
        Field(
            description="User's home directory paths",
            default_factory=list,
        ),
    ]
    groups: Annotated[
        List[str], Field(description="List of groups the user belongs to")
    ] = []
    user_policies: Annotated[
        List[PolicyModel], Field(description="User's policies (home and system)")
    ] = []
    group_policies: Annotated[
        List[PolicyModel], Field(description="Policies from associated groups")
    ] = []
    total_policies: Annotated[
        int, Field(ge=0, description="Total number of policies")
    ] = 0
    accessible_paths: Annotated[
        List[str], Field(description="All paths accessible by the user")
    ] = []
