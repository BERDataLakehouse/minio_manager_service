"""Tests for the per-tenant Trino catalog reconciler."""

import os
from unittest.mock import MagicMock, patch

import pytest

from service.exceptions import PolarisOperationError
from trino_integration.reconciler import (
    ADMIN_TOKEN_KEY,
    TrinoCatalogReconciler,
    _read_env_or_file,
    _render_create_catalog_sql,
    build_iceberg_catalog_properties,
)


# === _read_env_or_file ===


class TestReadEnvOrFile:
    """Verify the docker-compose-friendly credential resolution.

    The reconciler accepts either a direct env var or a ``_FILE``-suffixed
    path so init containers can inject server-generated credentials into a
    shared volume without rebuilding MMS or hardcoding secrets in compose
    files.
    """

    def test_direct_env_wins_over_file(self, tmp_path):
        path = tmp_path / "secret.txt"
        path.write_text("from-file")
        with patch.dict(
            os.environ,
            {"X_TEST_CRED": "from-env", "X_TEST_CRED_FILE": str(path)},
            clear=False,
        ):
            assert _read_env_or_file("X_TEST_CRED") == "from-env"

    def test_file_used_when_env_unset(self, tmp_path):
        path = tmp_path / "secret.txt"
        path.write_text("from-file\n")  # trailing newline must be stripped
        with patch.dict(os.environ, {"X_TEST_CRED_FILE": str(path)}, clear=False):
            os.environ.pop("X_TEST_CRED", None)
            assert _read_env_or_file("X_TEST_CRED") == "from-file"

    def test_returns_empty_when_both_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("X_TEST_CRED", None)
            os.environ.pop("X_TEST_CRED_FILE", None)
            assert _read_env_or_file("X_TEST_CRED") == ""

    def test_returns_empty_when_file_missing(self, tmp_path):
        # File reference set, but path doesn't exist on disk: don't raise,
        # log + return empty so the reconciler's _require_global_credentials
        # surfaces a clear error instead.
        with patch.dict(
            os.environ,
            {"X_TEST_CRED_FILE": str(tmp_path / "does_not_exist.txt")},
            clear=False,
        ):
            os.environ.pop("X_TEST_CRED", None)
            assert _read_env_or_file("X_TEST_CRED") == ""

    def test_empty_direct_env_falls_back_to_file(self, tmp_path):
        # Empty string is treated the same as unset (matches docker-compose's
        # `env: ""` semantics) so the file fallback wins.
        path = tmp_path / "secret.txt"
        path.write_text("from-file")
        with patch.dict(
            os.environ,
            {"X_TEST_CRED": "", "X_TEST_CRED_FILE": str(path)},
            clear=False,
        ):
            assert _read_env_or_file("X_TEST_CRED") == "from-file"


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
        props = build_iceberg_catalog_properties(**_base_kwargs())
        assert props["iceberg.security"] == "read_only"

    def test_vended_credentials_disabled(self):
        # Trino vended-credentials integration is unreliable; rely on the
        # static MinIO keys above instead.
        props = build_iceberg_catalog_properties(**_base_kwargs())
        assert props["iceberg.rest-catalog.vended-credentials-enabled"] == "false"

    def test_token_refresh_enabled(self):
        # Without this, the Iceberg connector caches a token at
        # catalog-creation time and queries fail an hour later when Polaris
        # rotates tokens.
        props = build_iceberg_catalog_properties(**_base_kwargs())
        assert props["iceberg.rest-catalog.oauth2.token-refresh-enabled"] == "true"

    def test_oauth2_server_uri_appended_when_v1_missing(self):
        kwargs = _base_kwargs()
        kwargs["polaris_catalog_uri"] = "http://polaris:8181/api/catalog"
        props = build_iceberg_catalog_properties(**kwargs)
        assert props["iceberg.rest-catalog.oauth2.server-uri"].endswith(
            "/api/catalog/v1/oauth/tokens"
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
        # Pattern matches the access-control plugin's tenant-alias rule.
        # Divergence would let the reconciler write catalogs the plugin
        # would later reject.
        for bad in [
            "Globalusers",
            "1tenant",
            "tenant.with.dots",
            "tenant-with-hyphens",
            "tenant/path",
            "",
            "a" * 64,
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
        # If a stored credential ever contained a single quote, the rendered
        # SQL must keep it inside the value rather than terminating the
        # literal early.
        sql = _render_create_catalog_sql(
            "globalusers",
            {"iceberg.rest-catalog.oauth2.credential": "abc'def"},
        )
        assert "abc''def" in sql


# === TrinoCatalogReconciler ===


def _make_reconciler(**overrides):
    defaults = dict(
        trino_host="trino-test",
        trino_port=8080,
        trino_admin_username="platform_admin",
        trino_admin_token="test-admin-token",
        polaris_catalog_uri="http://polaris:8181/api/catalog",
        s3_endpoint="http://minio:9000",
        global_s3_access_key="global-ak",
        global_s3_secret_key="global-sk",
        global_polaris_client_id="global-cid",
        global_polaris_client_secret="global-secret",
    )
    defaults.update(overrides)
    return TrinoCatalogReconciler(**defaults)


class TestReconcilerEnvFilePickup:
    """Reconciler picks up Polaris credentials from ``_FILE``-routed env.

    This is the docker-compose path where an init container writes the
    server-generated client_id/secret into a shared volume and MMS reads
    them at construction time.
    """

    def test_polaris_credentials_resolved_from_file(self, tmp_path):
        cid = tmp_path / "polaris_client_id.txt"
        sec = tmp_path / "polaris_client_secret.txt"
        cid.write_text("file-cid")
        sec.write_text("file-sec")
        env = {
            "TRINO_HOST": "trino-test",
            "TRINO_PORT": "8080",
            "TRINO_ADMIN_TOKEN": "test-admin-token",
            "POLARIS_CATALOG_URI": "http://polaris:8181/api/catalog",
            "MINIO_ENDPOINT": "http://minio:9000",
            "TRINO_GLOBAL_S3_ACCESS_KEY": "global-ak",
            "TRINO_GLOBAL_S3_SECRET_KEY": "global-sk",
            "TRINO_GLOBAL_POLARIS_CLIENT_ID_FILE": str(cid),
            "TRINO_GLOBAL_POLARIS_CLIENT_SECRET_FILE": str(sec),
        }
        with patch.dict(os.environ, env, clear=False):
            for k in (
                "TRINO_GLOBAL_POLARIS_CLIENT_ID",
                "TRINO_GLOBAL_POLARIS_CLIENT_SECRET",
            ):
                os.environ.pop(k, None)
            reconciler = TrinoCatalogReconciler()

        assert reconciler._global_polaris_client_id == "file-cid"
        assert reconciler._global_polaris_client_secret == "file-sec"


class TestReconcileTenantPreconditions:
    @pytest.mark.asyncio
    async def test_raises_when_admin_token_missing(self):
        reconciler = _make_reconciler(trino_admin_token="")
        with pytest.raises(PolarisOperationError, match="TRINO_ADMIN_TOKEN"):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_polaris_uri_missing(self):
        reconciler = _make_reconciler(polaris_catalog_uri="")
        with pytest.raises(PolarisOperationError, match="POLARIS_CATALOG_URI"):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_s3_endpoint_missing(self):
        reconciler = _make_reconciler(s3_endpoint="")
        with pytest.raises(PolarisOperationError, match="MINIO_ENDPOINT"):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_global_polaris_credential_missing(self):
        reconciler = _make_reconciler(global_polaris_client_secret="")
        with pytest.raises(
            PolarisOperationError, match="TRINO_GLOBAL_POLARIS_CLIENT_SECRET"
        ):
            await reconciler.reconcile_tenant("globalusers")

    @pytest.mark.asyncio
    async def test_raises_when_global_s3_credentials_missing(self):
        reconciler = _make_reconciler(global_s3_access_key="")
        with pytest.raises(PolarisOperationError, match="TRINO_GLOBAL_S3_ACCESS_KEY"):
            await reconciler.reconcile_tenant("globalusers")


def _patch_dbapi(catalogs_present=()):
    """Build a dbapi patch where SHOW CATALOGS returns ``catalogs_present``.

    Returns the patch context manager and the cursor mock so tests can
    assert on executed SQL after the ``with`` block.
    """
    cm = patch("trino_integration.reconciler.trino.dbapi")
    mock_dbapi = cm.start()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [(name,) for name in catalogs_present]
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.__exit__.return_value = None
    mock_dbapi.connect.return_value = mock_conn
    return cm, mock_dbapi, mock_cursor


class TestReconcileTenantDefault:
    """Default ``force=False`` path: pre-check first, only CREATE if missing."""

    @pytest.mark.asyncio
    async def test_skips_when_catalog_already_exists(self):
        reconciler = _make_reconciler()
        cm, _, mock_cursor = _patch_dbapi(catalogs_present=["globalusers", "kbase"])
        try:
            alias = await reconciler.reconcile_tenant("globalusers")
        finally:
            cm.stop()

        assert alias == "globalusers"
        # Only SHOW CATALOGS ran — no DROP, no CREATE.
        executed_sql = [c.args[0] for c in mock_cursor.execute.call_args_list]
        assert executed_sql == ["SHOW CATALOGS"]

    @pytest.mark.asyncio
    async def test_creates_when_catalog_missing(self):
        reconciler = _make_reconciler()
        cm, _, mock_cursor = _patch_dbapi(catalogs_present=["kbase"])
        try:
            alias = await reconciler.reconcile_tenant("globalusers")
        finally:
            cm.stop()

        assert alias == "globalusers"
        executed_sql = [c.args[0] for c in mock_cursor.execute.call_args_list]
        # SHOW CATALOGS pre-check, then CREATE — no DROP.
        assert len(executed_sql) == 2
        assert executed_sql[0] == "SHOW CATALOGS"
        assert executed_sql[1].startswith("CREATE CATALOG IF NOT EXISTS")
        assert "globalusers" in executed_sql[1]
        # Global service-identity creds are spliced into the CREATE statement.
        assert "global-cid:global-secret" in executed_sql[1]
        assert "global-ak" in executed_sql[1]
        assert "global-sk" in executed_sql[1]


class TestReconcileTenantForce:
    """``force=True`` path: drop-then-create regardless of current state."""

    @pytest.mark.asyncio
    async def test_force_issues_drop_then_create_when_catalog_exists(self):
        reconciler = _make_reconciler()
        cm, mock_dbapi, mock_cursor = _patch_dbapi(catalogs_present=["globalusers"])
        try:
            alias = await reconciler.reconcile_tenant("globalusers", force=True)
        finally:
            cm.stop()

        assert alias == "globalusers"

        # Connection used the admin identity + token via extra_credential.
        connect_kwargs = mock_dbapi.connect.call_args.kwargs
        assert connect_kwargs["host"] == "trino-test"
        assert connect_kwargs["port"] == 8080
        assert connect_kwargs["user"] == "platform_admin"
        assert connect_kwargs["extra_credential"] == [
            (ADMIN_TOKEN_KEY, "test-admin-token")
        ]

        # No SHOW CATALOGS pre-check — force skips it. DROP then CREATE.
        executed_sql = [c.args[0] for c in mock_cursor.execute.call_args_list]
        assert len(executed_sql) == 2
        assert executed_sql[0].startswith("DROP CATALOG IF EXISTS")
        assert "globalusers" in executed_sql[0]
        assert executed_sql[1].startswith("CREATE CATALOG IF NOT EXISTS")
        assert "globalusers" in executed_sql[1]

    @pytest.mark.asyncio
    async def test_force_drops_then_creates_when_catalog_missing(self):
        # DROP IF EXISTS is a no-op when missing; behavior matches "exists"
        # case so rotation flow is uniform regardless of starting state.
        reconciler = _make_reconciler()
        cm, _, mock_cursor = _patch_dbapi(catalogs_present=[])
        try:
            await reconciler.reconcile_tenant("globalusers", force=True)
        finally:
            cm.stop()

        executed_sql = [c.args[0] for c in mock_cursor.execute.call_args_list]
        assert len(executed_sql) == 2
        assert executed_sql[0].startswith("DROP CATALOG IF EXISTS")
        assert executed_sql[1].startswith("CREATE CATALOG IF NOT EXISTS")


class TestTenantCatalogExists:
    @pytest.mark.asyncio
    async def test_tenant_catalog_exists_checks_show_catalogs(self):
        reconciler = _make_reconciler()

        with patch("trino_integration.reconciler.trino.dbapi") as mock_dbapi:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = [("globalusers",), ("kbase",)]
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.__enter__.return_value = mock_conn
            mock_conn.__exit__.return_value = None
            mock_dbapi.connect.return_value = mock_conn

            assert await reconciler.tenant_catalog_exists("globalusers") is True

    @pytest.mark.asyncio
    async def test_tenant_catalog_exists_returns_false_when_missing(self):
        reconciler = _make_reconciler()

        with patch("trino_integration.reconciler.trino.dbapi") as mock_dbapi:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = [("kbase",)]
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.__enter__.return_value = mock_conn
            mock_conn.__exit__.return_value = None
            mock_dbapi.connect.return_value = mock_conn

            assert await reconciler.tenant_catalog_exists("globalusers") is False


class TestDeprovisionTenant:
    @pytest.mark.asyncio
    async def test_issues_single_drop_catalog(self):
        reconciler = _make_reconciler()

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
    async def test_raises_when_admin_token_missing(self):
        reconciler = _make_reconciler(trino_admin_token="")
        with pytest.raises(PolarisOperationError, match="TRINO_ADMIN_TOKEN"):
            await reconciler.deprovision_tenant("globalusers")
