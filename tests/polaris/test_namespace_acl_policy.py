"""Tests for namespace ACL MinIO policy generation."""

import pytest

from polaris.namespace_acl_policy import (
    NamespaceAclPolicyGrant,
    build_namespace_acl_policy,
    compact_policy_size_bytes,
    namespace_acl_policy_name,
    namespace_acl_storage_path,
)
from s3.models.s3_config import S3Config


@pytest.fixture
def s3_config():
    """Create S3Config for policy tests."""
    return S3Config(
        endpoint="http://minio:9002",
        access_key="minio",
        secret_key="minio123",
        secure=False,
    )


def test_namespace_acl_policy_name():
    assert namespace_acl_policy_name("alice") == "namespace-acl-alice"


def test_namespace_acl_storage_path(s3_config):
    assert (
        namespace_acl_storage_path(s3_config, "kbase", ["geo", "curated"])
        == "s3a://cdm-lake/tenant-sql-warehouse/kbase/iceberg/geo/curated"
    )


def test_build_read_policy(s3_config):
    policy = build_namespace_acl_policy(
        "alice",
        [
            NamespaceAclPolicyGrant(
                tenant_name="kbase",
                namespace_parts=("shared_data",),
                access_level="read",
            )
        ],
        s3_config,
    )
    policy_dict = policy.policy_document.to_dict()
    statements = policy_dict["Statement"]

    assert policy.policy_name == "namespace-acl-alice"
    assert {stmt["Action"] for stmt in statements} == {
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
    }

    list_bucket = next(stmt for stmt in statements if stmt["Action"] == "s3:ListBucket")
    assert list_bucket["Condition"]["StringLike"]["s3:prefix"] == [
        "tenant-sql-warehouse/kbase/iceberg/shared_data",
        "tenant-sql-warehouse/kbase/iceberg/shared_data/*",
    ]

    get_object = next(stmt for stmt in statements if stmt["Action"] == "s3:GetObject")
    assert get_object["Resource"] == [
        "arn:aws:s3:::cdm-lake/tenant-sql-warehouse/kbase/iceberg/shared_data",
        "arn:aws:s3:::cdm-lake/tenant-sql-warehouse/kbase/iceberg/shared_data/*",
    ]


def test_build_write_policy(s3_config):
    policy = build_namespace_acl_policy(
        "alice",
        [
            NamespaceAclPolicyGrant(
                tenant_name="kbase",
                namespace_parts=("shared_data",),
                access_level="write",
            )
        ],
        s3_config,
    )
    actions = {stmt["Action"] for stmt in policy.policy_document.to_dict()["Statement"]}

    assert actions == {
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
    }


def test_compact_policy_size_bytes_is_nonzero(s3_config):
    policy = build_namespace_acl_policy(
        "alice",
        [
            NamespaceAclPolicyGrant(
                tenant_name="kbase",
                namespace_parts=("shared_data",),
                access_level="read",
            )
        ],
        s3_config,
    )

    assert compact_policy_size_bytes(policy) > 0
