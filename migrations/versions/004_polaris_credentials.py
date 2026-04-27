"""Add encrypted Polaris credential cache.

Revision ID: 004
Revises: 003
Create Date: 2026-04-25
"""

from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    op.execute("""
        CREATE TABLE IF NOT EXISTS polaris_user_credentials (
            username         TEXT PRIMARY KEY,
            client_id        TEXT NOT NULL,
            client_secret    BYTEA NOT NULL,
            personal_catalog TEXT NOT NULL,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS polaris_user_credentials;")
