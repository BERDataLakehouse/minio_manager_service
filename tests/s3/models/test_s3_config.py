"""Tests for the minio.models.s3_config module."""

import pytest

from s3.models.s3_config import S3Config


def test_config_imports():
    """Test that s3_config module can be imported."""
    from s3.models import s3_config

    assert s3_config is not None


def test_valid_config():
    """Test S3Config with valid values."""
    config = S3Config(
        endpoint="http://localhost:9002",
        access_key="minio",
        secret_key="minio123",
    )
    assert str(config.endpoint) == "http://localhost:9002/"
    assert config.access_key == "minio"
    assert config.default_bucket == "cdm-lake"


class TestWarehousePrefixValidation:
    """Tests for warehouse prefix validation (covers lines 137-138)."""

    def test_invalid_warehouse_prefix_with_path_traversal(self):
        """Test that warehouse prefix with '..' raises ValueError."""
        with pytest.raises(ValueError, match="path separators"):
            S3Config(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                users_sql_warehouse_prefix="foo/../bar",
            )

    def test_invalid_warehouse_prefix_with_backslash(self):
        """Test that warehouse prefix with backslash raises ValueError."""
        with pytest.raises(ValueError, match="path separators"):
            S3Config(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                users_general_warehouse_prefix="foo\\bar",
            )

    def test_invalid_tenant_warehouse_prefix(self):
        """Test tenant warehouse prefix validation."""
        with pytest.raises(ValueError, match="path separators"):
            S3Config(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                tenant_general_warehouse_prefix="..sneaky",
            )


class TestDefaultBucketValidation:
    """Tests for default_bucket validation (covers lines 146-147)."""

    def test_invalid_bucket_name_with_dots(self):
        """Test that bucket name with dots raises ValueError."""
        with pytest.raises(ValueError, match="unsupported"):
            S3Config(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                default_bucket="my.bucket.name",
            )

    def test_invalid_bucket_name_too_short(self):
        """Test that bucket name shorter than 3 chars raises ValueError."""
        with pytest.raises(ValueError):
            S3Config(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                default_bucket="ab",
            )

    def test_invalid_bucket_name_with_uppercase(self):
        """Test that bucket name with uppercase raises ValueError."""
        with pytest.raises(ValueError, match="lowercase"):
            S3Config(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                default_bucket="MyBucket",
            )
