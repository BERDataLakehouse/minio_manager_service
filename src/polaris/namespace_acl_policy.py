"""MinIO policy builder for Polaris namespace ACL grants."""

import json
from dataclasses import dataclass
from typing import Sequence

from polaris.constants import ICEBERG_STORAGE_SUBDIRECTORY
from polaris.namespace_acl_store import (
    normalize_access_level,
    normalize_namespace_parts,
)
from s3.core.policy_builder import PolicyBuilder
from s3.models.policy import PolicyDocument, PolicyModel, PolicyPermissionLevel
from s3.models.s3_config import S3Config
from s3.utils.validators import NAMESPACE_ACL_POLICY_PREFIX, validate_policy_name

MAX_NAMESPACE_ACL_POLICY_BYTES = 18 * 1024


@dataclass(frozen=True)
class NamespaceAclPolicyGrant:
    """Storage permission needed for one namespace ACL grant."""

    tenant_name: str
    namespace_parts: tuple[str, ...]
    access_level: str


def namespace_acl_policy_name(username: str) -> str:
    """Return the consolidated namespace ACL MinIO policy name for a user."""
    return validate_policy_name(f"{NAMESPACE_ACL_POLICY_PREFIX}{username}")


def namespace_acl_storage_path(
    config: S3Config,
    tenant_name: str,
    namespace_parts: Sequence[str],
) -> str:
    """Return the S3 path covered by a namespace ACL policy grant."""
    normalized_namespace = normalize_namespace_parts(namespace_parts)
    namespace_path = "/".join(normalized_namespace)
    return (
        f"s3a://{config.default_bucket}/"
        f"{config.tenant_sql_warehouse_prefix}/"
        f"{tenant_name}/"
        f"{ICEBERG_STORAGE_SUBDIRECTORY}/"
        f"{namespace_path}"
    )


def build_namespace_acl_policy(
    username: str,
    grants: Sequence[NamespaceAclPolicyGrant],
    config: S3Config,
) -> PolicyModel:
    """Build a consolidated MinIO policy document for a user's namespace ACLs."""
    policy = PolicyModel(
        policy_name=namespace_acl_policy_name(username),
        policy_document=PolicyDocument(statement=[]),
    )

    for grant in grants:
        access_level = normalize_access_level(grant.access_level)
        permission_level = (
            PolicyPermissionLevel.READ
            if access_level == "read"
            else PolicyPermissionLevel.WRITE
        )
        path = namespace_acl_storage_path(
            config,
            grant.tenant_name,
            grant.namespace_parts,
        )
        policy = (
            PolicyBuilder(policy, config.default_bucket)
            .add_path_access(path, permission_level, new_policy=True)
            .build()
        )

    return policy


def compact_policy_size_bytes(policy: PolicyModel) -> int:
    """Return the compact JSON policy size in bytes."""
    compact = json.dumps(
        policy.policy_document.to_dict(),
        separators=(",", ":"),
        sort_keys=True,
    )
    return len(compact.encode("utf-8"))
