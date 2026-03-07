"""Tests for the minio.models.minio_config module."""

import pytest

from src.minio.models.minio_config import MinIOConfig


def test_config_imports():
    """Test that minio_config module can be imported."""
    from src.minio.models import minio_config

    assert minio_config is not None


def test_valid_config():
    """Test MinIOConfig with valid values."""
    config = MinIOConfig(
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
            MinIOConfig(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                users_sql_warehouse_prefix="foo/../bar",
            )

    def test_invalid_warehouse_prefix_with_backslash(self):
        """Test that warehouse prefix with backslash raises ValueError."""
        with pytest.raises(ValueError, match="path separators"):
            MinIOConfig(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                users_general_warehouse_prefix="foo\\bar",
            )

    def test_invalid_tenant_warehouse_prefix(self):
        """Test tenant warehouse prefix validation."""
        with pytest.raises(ValueError, match="path separators"):
            MinIOConfig(
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
            MinIOConfig(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                default_bucket="my.bucket.name",
            )

    def test_invalid_bucket_name_too_short(self):
        """Test that bucket name shorter than 3 chars raises ValueError."""
        with pytest.raises(ValueError):
            MinIOConfig(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                default_bucket="ab",
            )

    def test_invalid_bucket_name_with_uppercase(self):
        """Test that bucket name with uppercase raises ValueError."""
        with pytest.raises(ValueError, match="lowercase"):
            MinIOConfig(
                endpoint="http://localhost:9002",
                access_key="minio",
                secret_key="minio123",
                default_bucket="MyBucket",
            )
