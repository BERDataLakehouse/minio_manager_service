"""Tests for the per-tenant Trino catalog reconciler.

The reconciler is small but security-relevant: every SQL statement it runs
goes through Trino's admin path (Phase 2). Tests cover:
- the catalog-properties builder produces the right keys + values
- catalog name validation rejects pathological inputs
- SQL rendering escapes single-quoted property values
- reconcile_tenant raises clear errors when prerequisite creds are missing
- reconcile_tenant fans out to the Trino dbapi via asyncio.to_thread with
  the right user / extra credential pair
- deprovision_tenant issues a single DROP CATALOG statement
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from credentials.polaris_store import PolarisCredentialRecord
from trino_integration.reconciler import (
    ADMIN_TOKEN_KEY,
    TrinoCatalogReconciler,
    _render_create_catalog_sql,
    build_iceberg_catalog_properties,
)
from service.exceptions import PolarisOperationError


# === build_iceberg_catalog_properties ===


def _base_kwargs():
    return dict(
        polaris_catalog_uri="http://polaris:8181/api/catalog",
        polaris_warehouse="tenant_globalusers",
        polaris_credential="cid:secret",
        s3_endpoint="http://minio:9000",
        s3_access_key="ak",
        s3_secret_key="sk",
    )


class TestBuildIcebergCatalogProperties:
    def test_required_keys_present(self):
        props = build_iceberg_catalog_properties(**_base_kwargs())
        assert props["iceberg.catalog.type"] == "rest"
        assert props["iceberg.rest-catalog.uri"] == "http://polaris:8181/api/catalog"
        assert props["iceberg.rest-catalog.warehouse"] == "tenant_globalusers"
        assert props["iceberg.rest-catalog.security"] == "OAUTH2"
        assert props["iceberg.rest-catalog.oauth2.credential"] == "cid:secret"
        assert props["iceberg.rest-catalog.oauth2.scope"] == "PRINCIPAL_ROLE:ALL"
        assert props["s3.aws-access-key"] == "ak"
        assert props["s3.aws-secret-key"] == "sk"

    def test_security_is_read_only(self):
        # Defense-in-depth invariant: tenant catalogs are read-only at the
        # engine level even before plugin / Polaris RBAC layers.
        props = build_iceberg_catalog_properties(**_base_kwargs())
        assert props["iceberg.security"] == "read_only"

    def test_vended_credentials_disabled(self):
        # Trino #27416 still open; vended creds are not honored by Trino,
        # so we must use the static MinIO keys above.
        props = build_iceberg_catalog_properties(**_base_kwargs())
        assert props["iceberg.rest-catalog.vended-credentials-enabled"] == "false"

    def test_token_refresh_enabled(self):
        props = build_iceberg_catalog_properties(**_base_kwargs())
        assert props["iceberg.rest-catalog.oauth2.token-refresh-enabled"] == "true"

    def test_oauth2_server_uri_appended_when_v1_missing(self):
        kwargs = _base_kwargs()
        kwargs["polaris_catalog_uri"] = "http://polaris:8181/api/catalog"
        props = build_iceberg_catalog_properties(**kwargs)
        assert props["iceberg.rest-catalog.oauth2.server-uri"].endswith(
            "/api/catalog/v1/oauth/tokens"
        )

    def test_oauth2_server_uri_when_v1_present(self):
        kwargs = _base_kwargs()
        kwargs["polaris_catalog_uri"] = "http://polaris:8181/api/v1"
        props = build_iceberg_catalog_properties(**kwargs)
        assert props["iceberg.rest-catalog.oauth2.server-uri"].endswith(
            "/api/v1/oauth/tokens"
        )

    def test_polaris_credential_required(self):
        kwargs = _base_kwargs()
        kwargs["polaris_credential"] = ""
        with pytest.raises(ValueError, match="polaris_credential"):
            build_iceberg_catalog_properties(**kwargs)

    def test_polaris_catalog_uri_required(self):
        kwargs = _base_kwargs()
        kwargs["polaris_catalog_uri"] = ""
        with pytest.raises(ValueError, match="polaris_catalog_uri"):
            build_iceberg_catalog_properties(**kwargs)


# === _render_create_catalog_sql ===


class TestRenderCreateCatalogSQL:
    def test_renders_create_catalog_with_quoted_alias(self):
        sql = _render_create_catalog_sql(
            "globalusers",
            {"iceberg.catalog.type": "rest"},
        )
        assert "CREATE CATALOG IF NOT EXISTS" in sql
        assert "globalusers" in sql
        assert "USING iceberg" in sql

    def test_rejects_invalid_catalog_name(self):
        # Pattern matches the access-control plugin's TENANT_ALIAS_PATTERN.
        # If these diverge, the plugin will reject otherwise-valid calls.
        for bad in [
            "Globalusers",  # uppercase
            "1tenant",  # starts with digit
            "tenant.with.dots",  # dots
            "tenant-with-hyphens",  # hyphens
            "tenant/path",  # slash
            "",  # empty
            "a" * 64,  # too long
        ]:
            with pytest.raises(ValueError, match="Invalid tenant catalog alias"):
                _render_create_catalog_sql(bad, {"iceberg.catalog.type": "rest"})

    def test_rejects_disallowed_property_keys(self):
        with pytest.raises(
            ValueError, match="Disallowed Iceberg catalog property keys"
        ):
            _render_create_catalog_sql(
                "globalusers",
                {"some.weird.injected": "value"},
            )

    def test_escapes_single_quotes_in_property_values(self):
        # If a stored credential ever contained a single quote (e.g. via
        # accidental DB write), the rendered SQL must keep it inside the
        # value rather than terminating the literal early.
        sql = _render_create_catalog_sql(
            "globalusers",
            {"iceberg.rest-catalog.oauth2.credential": "abc'def"},
        )
        # Should contain doubled-up single quote inside the value
        assert "abc''def" in sql


# === TrinoCatalogReconciler ===


@pytest.fixture
def reconciler_deps():
    s3_store = AsyncMock()
    polaris_store = AsyncMock()
    return s3_store, polaris_store


def _make_reconciler(s3_store, polaris_store, **overrides):
    defaults = dict(
        trino_host="trino-test",
        trino_port=8080,
        trino_admin_username="platform_admin",
        trino_admin_token="test-admin-token",
        polaris_catalog_uri="http://polaris:8181/api/catalog",
        s3_endpoint="http://minio:9000",
    )
    defaults.update(overrides)
    return TrinoCatalogReconciler(
        s3_credential_store=s3_store,
        polaris_credential_store=polaris_store,
        **defaults,
    )


class TestReconcileTenantPreconditions:
    @pytest.mark.asyncio
    async def test_raises_when_admin_token_missing(self, reconciler_deps):
        s3, polaris = reconciler_deps
        reconciler = _make_reconciler(s3, polaris, trino_admin_token="")
        with pytest.raises(PolarisOperationError, match="TRINO_ADMIN_TOKEN"):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_polaris_uri_missing(self, reconciler_deps):
        s3, polaris = reconciler_deps
        reconciler = _make_reconciler(s3, polaris, polaris_catalog_uri="")
        with pytest.raises(PolarisOperationError, match="POLARIS_CATALOG_URI"):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_s3_endpoint_missing(self, reconciler_deps):
        s3, polaris = reconciler_deps
        reconciler = _make_reconciler(s3, polaris, s3_endpoint="")
        with pytest.raises(PolarisOperationError, match="MINIO_ENDPOINT"):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_s3_credentials_missing(self, reconciler_deps):
        s3, polaris = reconciler_deps
        s3.get_credentials = AsyncMock(return_value=None)
        polaris.get_credentials = AsyncMock(
            return_value=PolarisCredentialRecord(
                client_id="cid",
                client_secret="secret",
                personal_catalog="tenant_globalusers",
            )
        )
        reconciler = _make_reconciler(s3, polaris)
        with pytest.raises(PolarisOperationError, match="S3 credentials"):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_polaris_credentials_missing(self, reconciler_deps):
        s3, polaris = reconciler_deps
        s3.get_credentials = AsyncMock(return_value=("ak", "sk"))
        polaris.get_credentials = AsyncMock(return_value=None)
        reconciler = _make_reconciler(s3, polaris)
        with pytest.raises(PolarisOperationError, match="Polaris credentials"):
            await reconciler.reconcile_tenant("globalusers")


class TestReconcileTenantHappyPath:
    @pytest.mark.asyncio
    async def test_tenant_catalog_exists_checks_show_catalogs(self, reconciler_deps):
        s3, polaris = reconciler_deps
        reconciler = _make_reconciler(s3, polaris)

        with patch("trino_integration.reconciler.trino.dbapi") as mock_dbapi:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.__enter__.return_value = mock_conn
            mock_conn.__exit__.return_value = None
            mock_cursor.fetchall.return_value = [("system",), ("globalusers",)]
            mock_dbapi.connect.return_value = mock_conn

            assert await reconciler.tenant_catalog_exists("globalusers") is True

        mock_cursor.execute.assert_called_once_with("SHOW CATALOGS")

    @pytest.mark.asyncio
    async def test_tenant_catalog_exists_returns_false_when_missing(
        self, reconciler_deps
    ):
        s3, polaris = reconciler_deps
        reconciler = _make_reconciler(s3, polaris)

        with patch("trino_integration.reconciler.trino.dbapi") as mock_dbapi:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.__enter__.return_value = mock_conn
            mock_conn.__exit__.return_value = None
            mock_cursor.fetchall.return_value = [("system",)]
            mock_dbapi.connect.return_value = mock_conn

            assert await reconciler.tenant_catalog_exists("globalusers") is False

    @pytest.mark.asyncio
    async def test_issues_drop_and_create_in_order(self, reconciler_deps):
        s3, polaris = reconciler_deps
        s3.get_credentials = AsyncMock(return_value=("svc-ak", "svc-sk"))
        polaris.get_credentials = AsyncMock(
            return_value=PolarisCredentialRecord(
                client_id="svc-cid",
                client_secret="svc-secret",
                personal_catalog="tenant_globalusers",
            )
        )
        reconciler = _make_reconciler(s3, polaris)

        # Mock the trino dbapi connection so no real network call happens.
        with patch("trino_integration.reconciler.trino.dbapi") as mock_dbapi:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.__enter__.return_value = mock_conn
            mock_conn.__exit__.return_value = None
            mock_dbapi.connect.return_value = mock_conn

            alias = await reconciler.reconcile_tenant("globalusers")

        assert alias == "globalusers"

        # Connection used the admin identity + token via extra_credential
        connect_kwargs = mock_dbapi.connect.call_args.kwargs
        assert connect_kwargs["host"] == "trino-test"
        assert connect_kwargs["port"] == 8080
        assert connect_kwargs["user"] == "platform_admin"
        assert connect_kwargs["extra_credential"] == [
            (ADMIN_TOKEN_KEY, "test-admin-token")
        ]

        # First statement is DROP, second is CREATE — drop-then-create
        # ensures rotated credentials always replace stale ones.
        executed_sql = [c.args[0] for c in mock_cursor.execute.call_args_list]
        assert len(executed_sql) == 2
        assert executed_sql[0].startswith("DROP CATALOG IF EXISTS")
        assert "globalusers" in executed_sql[0]
        assert executed_sql[1].startswith("CREATE CATALOG IF NOT EXISTS")
        assert "globalusers" in executed_sql[1]
        assert "USING iceberg" in executed_sql[1]
        # Service-identity creds are spliced into the CREATE statement
        assert "svc-cid:svc-secret" in executed_sql[1]
        assert "svc-ak" in executed_sql[1]
        assert "svc-sk" in executed_sql[1]


class TestDeprovisionTenant:
    @pytest.mark.asyncio
    async def test_issues_single_drop_catalog(self, reconciler_deps):
        s3, polaris = reconciler_deps
        reconciler = _make_reconciler(s3, polaris)

        with patch("trino_integration.reconciler.trino.dbapi") as mock_dbapi:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.__enter__.return_value = mock_conn
            mock_conn.__exit__.return_value = None
            mock_dbapi.connect.return_value = mock_conn

            alias = await reconciler.deprovision_tenant("globalusers")

        assert alias == "globalusers"
        executed_sql = [c.args[0] for c in mock_cursor.execute.call_args_list]
        assert executed_sql == ['DROP CATALOG IF EXISTS "globalusers"']

    @pytest.mark.asyncio
    async def test_raises_when_admin_token_missing(self, reconciler_deps):
        s3, polaris = reconciler_deps
        reconciler = _make_reconciler(s3, polaris, trino_admin_token="")
        with pytest.raises(PolarisOperationError, match="TRINO_ADMIN_TOKEN"):
            await reconciler.deprovision_tenant("globalusers")
