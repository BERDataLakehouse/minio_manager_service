"""Alembic environment configuration for minio_manager_service.

When ``MMS_MIGRATION_DB_HOST`` is set, migrations connect directly to that
host (typically the postgres primary, bypassing PgBouncer). Otherwise the
URL falls back to ``MMS_DB_*``. The migration-dedicated env var exists
because PgBouncer's transaction-mode pooling can break Alembic patterns
that rely on session-scoped state (advisory locks, SET LOCAL, etc.).
"""

import os
from logging.config import fileConfig
from urllib.parse import quote_plus

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

# Skip logging reconfiguration when called programmatically from the app
# (the app has already configured logging; fileConfig would overwrite it).
if config.attributes.get("configure_logger", True):
    if config.config_file_name is not None:
        fileConfig(config.config_file_name)

target_metadata = None


def _get_database_url() -> str:
    """Build PostgreSQL URL for Alembic.

    Resolution order: MMS_MIGRATION_DB_HOST/PORT > MMS_DB_HOST/PORT. The
    dbname comes from MMS_MIGRATION_DB_NAME if set (typically the real `mms`
    database, which PgBouncer hides behind the `mms_rw` alias), else
    MMS_DB_NAME. Alembic must talk to the underlying Postgres database, not
    a PgBouncer alias — same logical DB, just a different routing layer.
    """
    host = os.environ.get("MMS_MIGRATION_DB_HOST") or os.environ.get(
        "MMS_DB_HOST", "localhost"
    )
    port = os.environ.get("MMS_MIGRATION_DB_PORT") or os.environ.get(
        "MMS_DB_PORT", "5432"
    )
    dbname = os.environ.get("MMS_MIGRATION_DB_NAME") or os.environ.get(
        "MMS_DB_NAME", "mms"
    )
    user = os.environ.get("MMS_DB_USER", "mms")
    password = quote_plus(os.environ.get("MMS_DB_PASSWORD", ""))
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{dbname}"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (SQL script generation)."""
    url = _get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table="alembic_version_mms",
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (direct database connection)."""
    url = _get_database_url()
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table="alembic_version_mms",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
