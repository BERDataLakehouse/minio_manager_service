"""Add Polaris namespace ACL grant tables.

Revision ID: 005
Revises: 004
Create Date: 2026-04-26
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create Polaris namespace ACL role, grant, and event tables."""
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS polaris_namespace_acl_roles (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_name TEXT NOT NULL,
            catalog_name TEXT NOT NULL,
            namespace_name TEXT NOT NULL,
            namespace_parts TEXT[] NOT NULL,
            access_level TEXT NOT NULL CHECK (access_level IN ('read', 'write')),
            catalog_role_name TEXT NOT NULL,
            principal_role_name TEXT NOT NULL,
            role_name_hash_len INTEGER NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_name, namespace_name, access_level),
            UNIQUE (catalog_role_name),
            UNIQUE (principal_role_name),
            CHECK (array_length(namespace_parts, 1) > 0),
            CHECK (role_name_hash_len IN (24, 32, 40)),
            CHECK (char_length(catalog_role_name) <= 256),
            CHECK (char_length(principal_role_name) <= 256)
        );
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_roles_tenant_namespace
            ON polaris_namespace_acl_roles (tenant_name, namespace_name);
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS polaris_namespace_acl_grants (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            role_id UUID NOT NULL REFERENCES polaris_namespace_acl_roles(id),
            tenant_name TEXT NOT NULL,
            catalog_name TEXT NOT NULL,
            namespace_name TEXT NOT NULL,
            namespace_parts TEXT[] NOT NULL,
            username TEXT NOT NULL,
            access_level TEXT NOT NULL CHECK (access_level IN ('read', 'write')),
            status TEXT NOT NULL CHECK (
                status IN ('pending', 'active', 'shadowed', 'sync_error', 'revoked')
            ),
            granted_by TEXT NOT NULL,
            granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_by TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            revoked_by TEXT,
            revoked_at TIMESTAMPTZ,
            last_synced_at TIMESTAMPTZ,
            last_sync_error TEXT,
            CHECK (array_length(namespace_parts, 1) > 0)
        );
        """
    )

    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_namespace_acl_grants_active_unique
            ON polaris_namespace_acl_grants (tenant_name, namespace_name, username)
            WHERE revoked_at IS NULL;
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_grants_username_status
            ON polaris_namespace_acl_grants (username, status)
            WHERE revoked_at IS NULL;
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_grants_tenant_namespace
            ON polaris_namespace_acl_grants (tenant_name, namespace_name);
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_grants_role_id
            ON polaris_namespace_acl_grants (role_id);
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS polaris_namespace_acl_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            grant_id UUID REFERENCES polaris_namespace_acl_grants(id) ON DELETE SET NULL,
            tenant_name TEXT NOT NULL,
            namespace_name TEXT NOT NULL,
            username TEXT,
            event_type TEXT NOT NULL CHECK (
                event_type IN (
                    'grant_created',
                    'grant_idempotent',
                    'access_level_changed',
                    'grant_shadowed',
                    'grant_activated',
                    'grant_revoked',
                    'sync_started',
                    'sync_failed',
                    'sync_healed',
                    'validation_failed'
                )
            ),
            old_access_level TEXT,
            new_access_level TEXT,
            old_status TEXT,
            new_status TEXT,
            actor TEXT NOT NULL,
            message TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_events_grant_id
            ON polaris_namespace_acl_events (grant_id);
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_events_tenant_namespace
            ON polaris_namespace_acl_events (tenant_name, namespace_name);
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_events_username
            ON polaris_namespace_acl_events (username);
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_namespace_acl_events_created_at
            ON polaris_namespace_acl_events (created_at);
        """
    )


def downgrade() -> None:
    """Drop Polaris namespace ACL tables."""
    op.execute("DROP TABLE IF EXISTS polaris_namespace_acl_events;")
    op.execute("DROP TABLE IF EXISTS polaris_namespace_acl_grants;")
    op.execute("DROP TABLE IF EXISTS polaris_namespace_acl_roles;")
