"""Tests for the Trino service-identity naming helpers.

Tenant-name validation lives in ``s3.utils.validators`` and is exercised by
``tests/s3/utils/test_validators.py``.
"""

from trino_integration.service_identity import (
    tenant_alias,
    tenant_warehouse_name,
)


class TestNamingHelpers:
    def test_tenant_alias_lowercases_and_replaces_disallowed_chars(self):
        assert tenant_alias("globalusers") == "globalusers"
        assert tenant_alias("GlobalUsers") == "globalusers"
        assert tenant_alias("team-data") == "team_data"
        assert tenant_alias("Mixed-Case_42") == "mixed_case_42"

    def test_tenant_alias_strips_leading_trailing_underscores(self):
        assert tenant_alias("--abc--") == "abc"

    def test_tenant_warehouse_name(self):
        assert tenant_warehouse_name("globalusers") == "tenant_globalusers"
        assert tenant_warehouse_name("kbase") == "tenant_kbase"
