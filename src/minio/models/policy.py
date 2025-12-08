"""Policy-related Pydantic models for MinIO Manager Service"""

import json
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing_extensions import Annotated


class PolicyEffect(str, Enum):
    """Policy effect enumeration."""

    ALLOW = "Allow"


class PolicyAction(str, Enum):
    """Common MinIO policy actions."""

    # Object actions
    GET_OBJECT = "s3:GetObject"
    PUT_OBJECT = "s3:PutObject"
    DELETE_OBJECT = "s3:DeleteObject"

    # Bucket actions
    LIST_BUCKET = "s3:ListBucket"

    # Administrative actions
    GET_BUCKET_LOCATION = "s3:GetBucketLocation"
    LIST_ALL_MY_BUCKETS = "s3:ListAllMyBuckets"

    # Wildcard
    ALL_ACTIONS = "s3:*"


class PolicyPermissionLevel(str, Enum):
    """Simplified permission levels."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class PolicyTarget(str, Enum):
    """Target types for policy operations."""

    USER = "user"
    GROUP = "group"


class PolicyType(str, Enum):
    """Types of policies in the system."""

    USER_HOME = "user_home"
    USER_SYSTEM = "user_system"
    GROUP_HOME = "group_home"
    GROUP_READ_ONLY = "group_read_only"


class PolicySectionType(str, Enum):
    """Policy sections for organized statement management."""

    # Administrative permissions that apply across all resources
    GLOBAL_PERMISSIONS = (
        "global_permissions"  # ListAllMyBuckets, GetBucketLocation - system-wide access
    )

    # Basic bucket listing and discovery permissions
    BUCKET_ACCESS = "bucket_access"  # ListBucket permissions for specific buckets - allows seeing bucket contents

    # Object retrieval permissions
    READ_PERMISSIONS = (
        "read_permissions"  # GetObject permissions - allows downloading/reading files
    )

    # Object creation and modification permissions
    WRITE_PERMISSIONS = (
        "write_permissions"  # PutObject permissions - allows uploading/creating files
    )

    # Object removal permissions
    DELETE_PERMISSIONS = (
        "delete_permissions"  # DeleteObject permissions - allows removing files
    )


# Permission level to action mappings
PERMISSION_LEVEL_ACTIONS = {
    PolicyPermissionLevel.READ: [
        PolicyAction.GET_OBJECT,
    ],
    PolicyPermissionLevel.WRITE: [
        PolicyAction.GET_OBJECT,
        PolicyAction.PUT_OBJECT,
        PolicyAction.DELETE_OBJECT,
    ],
    PolicyPermissionLevel.ADMIN: [PolicyAction.ALL_ACTIONS],
}


class PolicyStatement(BaseModel):
    """Individual policy statement."""

    model_config = ConfigDict(frozen=True)

    effect: Annotated[PolicyEffect, Field(description="Allow only")]
    action: Annotated[
        PolicyAction,
        Field(description="Action to allow/deny"),
    ]
    resource: Annotated[Union[str, List[str]], Field(description="Resources affected")]
    condition: Annotated[
        Optional[Dict[str, Any]], Field(default=None, description="Conditional logic")
    ]
    principal: Annotated[
        Optional[Union[str, List[str]]],
        Field(default=None, description="Principal (for resource policies)"),
    ]

    @classmethod
    def from_dict(cls, stmt_dict: Dict[str, Any]) -> "PolicyStatement":
        """Create PolicyStatement from dictionary with single-action enforcement."""
        raw_actions = stmt_dict["Action"]
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]

        if len(raw_actions) > 1:
            raise ValueError(f"Policy has multiple actions: {raw_actions}")

        action = raw_actions[0]

        try:
            policy_action = PolicyAction(action)
        except ValueError:
            raise ValueError(f"Unsupported policy action: {action}")

        return cls(
            effect=PolicyEffect(stmt_dict["Effect"]),
            action=policy_action,
            resource=stmt_dict["Resource"],
            condition=stmt_dict.get("Condition"),
            principal=stmt_dict.get("Principal"),
        )


class PolicyDocument(BaseModel):
    """Policy document structure."""

    version: Annotated[
        str, Field(default="2012-10-17", description="Policy language version")
    ] = "2012-10-17"
    statement: Annotated[List[PolicyStatement], Field(description="Policy statements")]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "Version": self.version,
            "Statement": [
                {
                    "Effect": stmt.effect.value,
                    "Action": stmt.action,
                    "Resource": stmt.resource,
                    **({"Condition": stmt.condition} if stmt.condition else {}),
                    **({"Principal": stmt.principal} if stmt.principal else {}),
                }
                for stmt in self.statement
            ],
        }

    @classmethod
    def from_dict(cls, policy_dict: Dict[str, Any]) -> "PolicyDocument":
        """Create from dictionary."""
        statements = []
        for stmt_dict in policy_dict.get("Statement", []):
            statements.append(PolicyStatement.from_dict(stmt_dict))

        return cls(
            version=policy_dict.get("Version", "2012-10-17"), statement=statements
        )


class PolicyModel(BaseModel):
    """Complete policy model with metadata."""

    policy_name: Annotated[
        str, Field(min_length=1, max_length=128, description="Policy name")
    ]
    policy_document: Annotated[PolicyDocument, Field(description="Policy document")]

    @field_validator("policy_name")
    @classmethod
    def validate_policy_name(cls, v):
        """Validate policy name format."""
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError(
                "Policy name can only contain letters, numbers, hyphens, underscores, and periods"
            )
        return v

    def to_minio_policy_json(self) -> str:
        """Convert to MinIO policy JSON string."""
        return json.dumps(self.policy_document.to_dict(), indent=2)
