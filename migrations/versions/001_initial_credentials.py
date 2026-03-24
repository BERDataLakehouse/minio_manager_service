"""Adopt existing user_credentials table into Alembic management.

Revision ID: 001
Revises:
Create Date: 2026-03-23
"""

from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    op.execute("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            username    TEXT PRIMARY KEY,
            access_key  TEXT NOT NULL,
            secret_key  BYTEA NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_credentials;")
