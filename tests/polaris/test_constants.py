"""Tests for the polaris.constants module."""

from polaris.constants import (
    ICEBERG_STORAGE_SUBDIRECTORY,
    PERSONAL_CATALOG_ADMIN_ROLE,
    normalize_group_name_for_polaris,
    personal_catalog_name,
    personal_principal_role,
    tenant_catalog_name,
    tenant_reader_catalog_role,
    tenant_reader_principal_role,
    tenant_writer_catalog_role,
    tenant_writer_principal_role,
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


class TestPersonalCatalogNaming:
    """Tests for the personal-catalog naming helpers."""

    def test_personal_catalog_admin_role_constant(self):
        assert PERSONAL_CATALOG_ADMIN_ROLE == "catalog_admin"

    def test_personal_catalog_name(self):
        assert personal_catalog_name("alice") == "user_alice"

    def test_personal_principal_role(self):
        assert personal_principal_role("alice") == "alice_role"


class TestTenantCatalogNaming:
    """Tests for the tenant-catalog naming helpers."""

    def test_tenant_catalog_name(self):
        assert tenant_catalog_name("globalusers") == "tenant_globalusers"

    def test_tenant_writer_catalog_role(self):
        assert tenant_writer_catalog_role("globalusers") == "globalusers_writer"

    def test_tenant_reader_catalog_role(self):
        assert tenant_reader_catalog_role("globalusers") == "globalusers_reader"

    def test_tenant_writer_principal_role(self):
        assert tenant_writer_principal_role("globalusers") == "globalusers_member"

    def test_tenant_reader_principal_role(self):
        assert tenant_reader_principal_role("globalusers") == "globalusersro_member"
