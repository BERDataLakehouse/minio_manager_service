"""Add website column to tenant_metadata table.

Revision ID: 003
Revises: 002
Create Date: 2026-03-26
"""

from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE tenant_metadata ADD COLUMN IF NOT EXISTS website TEXT;")


def downgrade() -> None:
    op.execute("ALTER TABLE tenant_metadata DROP COLUMN IF EXISTS website;")
