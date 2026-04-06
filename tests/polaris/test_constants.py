"""Tests for the polaris.constants module."""

from polaris.constants import (
    ICEBERG_STORAGE_SUBDIRECTORY,
    normalize_group_name_for_polaris,
)


class TestIcebergStorageSubdirectory:
    """Tests for the ICEBERG_STORAGE_SUBDIRECTORY constant."""

    def test_value(self):
        assert ICEBERG_STORAGE_SUBDIRECTORY == "iceberg"


class TestNormalizeGroupNameForPolaris:
    """Tests for normalize_group_name_for_polaris."""

    def test_regular_group(self):
        base, is_ro = normalize_group_name_for_polaris("kbase")
        assert base == "kbase"
        assert is_ro is False

    def test_ro_group(self):
        base, is_ro = normalize_group_name_for_polaris("kbasero")
        assert base == "kbase"
        assert is_ro is True

    def test_globalusers(self):
        base, is_ro = normalize_group_name_for_polaris("globalusers")
        assert base == "globalusers"
        assert is_ro is False

    def test_globalusersro(self):
        base, is_ro = normalize_group_name_for_polaris("globalusersro")
        assert base == "globalusers"
        assert is_ro is True

    def test_just_ro(self):
        """Edge case: group named exactly 'ro'."""
        base, is_ro = normalize_group_name_for_polaris("ro")
        assert base == ""
        assert is_ro is True
