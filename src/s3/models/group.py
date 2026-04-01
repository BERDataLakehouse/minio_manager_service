from typing import Annotated, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..utils.validators import validate_group_name


class GroupModel(BaseModel):
    """
    Group model representing a MinIO group.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )

    group_name: Annotated[
        str,
        Field(
            min_length=2,
            max_length=64,
            description="Unique group name identifier",
            examples=["scientists", "admin", "data_readers"],
        ),
    ]
    members: Annotated[
        List[str],
        Field(
            default_factory=list,
            description="List of usernames that belong to this group",
        ),
    ]
    policy_name: Annotated[
        Optional[str],
        Field(
            default=None, description="Name of the IAM policy attached to this group"
        ),
    ]

    @field_validator("group_name")
    @classmethod
    def validate_group_name_format(cls, v: str) -> str:
        """Validate group name using centralized validator."""
        return validate_group_name(v)

    @property
    def member_count(self) -> int:
        """Get the number of members in the group."""
        return len(self.members)

    @property
    def is_empty(self) -> bool:
        """Check if the group has no members."""
        return self.member_count == 0
