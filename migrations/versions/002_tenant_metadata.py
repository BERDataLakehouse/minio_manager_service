"""Add user_profiles, tenant_metadata, and tenant_stewards tables.

Revision ID: 002
Revises: 001
Create Date: 2026-03-23
"""

from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # User profiles: email captured at auth time
    # (KBase batch API only returns display names)
    op.execute("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            username        TEXT PRIMARY KEY,
            display_name    TEXT,
            email           TEXT,
            captured_at     TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """)

    # Tenant metadata: display name, description, and audit fields
    op.execute("""
        CREATE TABLE IF NOT EXISTS tenant_metadata (
            tenant_name     TEXT PRIMARY KEY,
            display_name    TEXT,
            description     TEXT,
            organization    TEXT,
            created_by      TEXT NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_by      TEXT
        );
    """)

    # Data steward assignments: which users are stewards for which tenants
    op.execute("""
        CREATE TABLE IF NOT EXISTS tenant_stewards (
            tenant_name     TEXT NOT NULL
                            REFERENCES tenant_metadata(tenant_name) ON DELETE CASCADE,
            username        TEXT NOT NULL,
            assigned_by     TEXT NOT NULL,
            assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_name, username)
        );
    """)

    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_tenant_stewards_username "
        "ON tenant_stewards(username);"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS tenant_stewards;")
    op.execute("DROP TABLE IF EXISTS tenant_metadata;")
    op.execute("DROP TABLE IF EXISTS user_profiles;")
