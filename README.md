# KBERDL Data Governance Service

[![codecov](https://codecov.io/gh/BERDataLakehouse/minio_manager_service/branch/main/graph/badge.svg)](https://codecov.io/gh/BERDataLakehouse/minio_manager_service)

A centralized FastAPI-based microservice that manages data governance within the BERDL platform. It programmatically provisions S3 storage policies and Apache Polaris (Iceberg REST) catalogs, providing dynamic credential management and unified access control for Spark applications without requiring code changes.

> **Note on naming.** The product is the **KBERDL Data Governance Service**. The repository, Python package (`minio-manager-service`), Docker service (`minio-manager`), and `MMS_*` environment variables retain the historical "MinIO Manager Service" name and will be renamed in a future cycle.

## Overview

The KBERDL Data Governance Service enables:

- **Dynamic Credential Management**: Issue and rotate per-user S3 and Polaris credentials on demand
- **Automated Policy Enforcement**: Maintain user and group-level inline IAM policies and Polaris RBAC roles with automatic updates
- **Dataset Isolation**: Provision isolated personal and tenant-level Iceberg catalogs natively
- **Data Governance**: Path-level and catalog-level access control with sharing capabilities between users and groups
- **Seamless Integration**: Zero-code changes for Spark applications; S3 and catalog credentials injected at runtime

## Key Features

### User Management

- Auto-create IAM users and Polaris principals with unique access/secret key pairs
- Credentials cached in PostgreSQL and returned on subsequent requests until explicitly rotated via `POST /credentials/rotate`
- Assign per-user isolated storage and catalogs:

  - `s3a://cdm-lake/users-general-warehouse/{username}/` - General data storage
  - `s3a://cdm-lake/users-sql-warehouse/{username}/` - Spark SQL / Delta warehouse
  - `user_{username}` - Personal Apache Polaris Iceberg catalog

### Tenant Management
- Tenants are the primary organizational unit, built on top of IAM groups
- Each tenant has metadata (display name, description, website, organization), members, and data stewards
- **Data stewards** can manage tenant membership and update metadata without being a full admin
- Members are assigned read-write or read-only access
- Provision dedicated tenant Iceberg catalogs in Polaris (`tenant_{groupname}`)
- Assign users to groups with inherited permissions (MinIO IAM + Polaris catalog roles)
- Tenant storage paths:
  - `s3a://cdm-lake/tenant-general-warehouse/{tenant}/` - General data storage
  - `s3a://cdm-lake/tenant-sql-warehouse/{tenant}/` - Spark SQL warehouse
  - Namespace prefix: `{tenant}_*` for Hive databases

### Tenant API (`/tenants`)
- `GET /tenants` - List all tenants with member counts and role flags
- `GET /tenants/{name}` - Full detail: metadata, stewards, members with profiles, storage paths
- `POST /tenants/{name}` - Create tenant metadata (idempotent)
- `PATCH /tenants/{name}` - Update metadata (steward or admin)
- `DELETE /tenants/{name}` - Delete metadata and cascade steward records
- `POST /tenants/{name}/members/{username}` - Add member (steward or admin)
- `DELETE /tenants/{name}/members/{username}` - Remove member
- `POST /tenants/{name}/stewards/{username}` - Assign steward (admin only)
- `DELETE /tenants/{name}/stewards/{username}` - Remove steward (admin only)
- `GET /tenants/{name}/members` - List members with profiles and access levels
- `GET /tenants/{name}/stewards` - List stewards with profiles

### Group Management
- Create and manage named IAM groups (the underlying primitive for tenants)
- Assign users to groups with inherited permissions
- Read-only groups via `{groupname}ro` convention
- Share group workspace: `s3a://cdm-lake/groups-general-warehouse/{groupname}/`

### Data Sharing
- Grant/revoke path-level access between users and groups for legacy Delta/Parquet data
- Manage Iceberg table sharing via native Polaris RBAC role assignments
- Fine-grained permissions: read-only or read-write group variants (`{group}` vs `{group}ro`)

### Security
- KBase authentication with role-based access control
- User credentials encrypted at rest in PostgreSQL (pgcrypto)
- Service holds only root/admin credentials for MinIO and Polaris
- Distributed locking via Redis for concurrent operations
- Credential rotation with blocking locks to prevent race conditions

## Quick Start

### Using Docker Compose

```bash
# Start the service stack
docker compose up -d

# View logs
docker compose logs -f minio-manager

# Access services
# - API docs: http://localhost:8010/docs
# - Ceph RadosGW (S3/IAM): http://localhost:9050
# - Polaris API: http://localhost:8182/api/catalog
```

> **Upgrading an existing local stack.** A named `postgres_data` volume now
> backs the postgres container, and the default database has changed from
> `hive` to `polaris`. If you have an existing local checkout, run
> `docker compose down -v` once before `docker compose up -d` so the new
> init scripts run against a clean data directory. This drops the previous
> ephemeral postgres state — production deployments are unaffected.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MINIO_ENDPOINT` | Yes | - | Ceph RadosGW endpoint URL (e.g., `http://ceph:8080`) |
| `MINIO_ROOT_USER` | Yes | - | S3/IAM access key |
| `MINIO_ROOT_PASSWORD` | Yes | - | S3/IAM secret key |
| `MMS_IAM_PATH_PREFIX` | No | `/data_governance_service` | IAM path prefix applied to all managed users and groups. Used to scope and list only service-managed entities (e.g. `PathPrefix` filtering). Must start and end with `/`. |
| `POLARIS_CATALOG_URI` | Yes | - | Polaris management API URI (e.g., `http://polaris:8181/api/catalog`) |
| `POLARIS_CREDENTIAL` | Yes | - | Polaris root/admin credentials (`client_id:client_secret`) |
| `KBASE_AUTH_URL` | No | `https://ci.kbase.us/services/auth/` | KBase authentication service URL |
| `KBASE_ADMIN_ROLES` | No | `KBASE_ADMIN` | Comma-separated admin roles |
| `KBASE_REQUIRED_ROLES` | No | `BERDL_USER` | Required roles for access |
| `REDIS_URL` | Yes | - | Redis URL (e.g., `redis://redis:6379`) |
| `MMS_DB_HOST` | Yes | - | PostgreSQL host for credential storage |
| `MMS_DB_PORT` | No | `5432` | PostgreSQL port |
| `MMS_DB_NAME` | Yes | - | PostgreSQL database name |
| `MMS_DB_USER` | Yes | - | PostgreSQL username |
| `MMS_DB_PASSWORD` | Yes | - | PostgreSQL password |
| `MMS_DB_ENCRYPTION_KEY` | Yes | - | Symmetric key for pgcrypto credential encryption. Use a strong random string; rotating this key requires re-encrypting existing rows. |

## JupyterHub Integration

The service integrates seamlessly with JupyterHub and Spark Connect:

1. **On user login**: JupyterHub startup scripts (`01-credentials.py`) call the governance API endpoints
2. **Credentials issued**: Service creates user/principal (if needed), caches credentials in PostgreSQL, and returns S3 and Polaris credentials
3. **Spark configured**: Credentials and catalog mappings injected into Spark session configuration
4. **Transparent access**: Spark jobs access Iceberg tables and S3 paths with strictly enforced permissions

Users can then use credentials to:
- Access their data via Spark (automatic)
- Share data with other users/groups via API

## Inline Policy Model

Unlike the previous MinIO implementation (which used named managed policies attached to users/groups), the Ceph implementation uses **inline policies** — policies embedded directly on the IAM entity they govern.

| Entity | Inline policy name | Purpose |
|--------|--------------------|---------|
| User | `home` | Access to the user's home prefix in the default bucket |
| User | `system` | System-level access needed by Spark (e.g. bucket-level ops) |
| Group | `group` | Access to the group's shared storage paths |

Inline policies are regenerated in place whenever access changes (e.g. a sharing grant is added or revoked). There are no standalone named policies and no policy management API endpoints.

## Migration from MinIO

A migration script is provided for moving IAM entities from a MinIO deployment to Ceph RadosGW:

```bash
PYTHONPATH=src python migrations/minio_to_s3_inline_iam.py \
    --src-endpoint http://localhost:9012 \
    --src-access-key minio \
    --src-secret-key minio123 \
    --dst-endpoint http://localhost:9050 \
    --dst-access-key test_access_key \
    --dst-secret-key test_access_secret \
    --dst-path-prefix /data_governance_service/ \
    [--dry-run]
```

The script reads named policies from MinIO via the `mc` CLI, derives user/group entities from the policy name prefixes (`user-home-policy-*`, `user-system-policy-*`, `group-policy-*`), creates the corresponding IAM entities on the Ceph target, and sets their inline policies. It is idempotent and safe to re-run.

## Database Migrations

The service uses Alembic for database schema management. Migrations run automatically on application startup (upgrade to head), so no manual steps are needed for normal deployments.

For manual migration management inside the container:

```bash
docker exec -it <container> bash

./scripts/migrate.sh status      # show current migration version
./scripts/migrate.sh history     # show all migrations
./scripts/migrate.sh up          # migrate to latest (head)
./scripts/migrate.sh up1         # migrate up one revision
./scripts/migrate.sh down1       # rollback one revision
./scripts/migrate.sh down-all    # revert ALL migrations (destructive, requires confirmation)

# For advanced alembic usage:
uv run alembic --help
```

## Testing

```bash
# Install dependencies
uv sync --locked

# Run all tests
uv run pytest tests

# Run with coverage
uv run pytest --cov=src tests/

# Run specific tests
uv run pytest tests/routes/test_credentials.py -v
```

## Documentation

- [Design Document](docs/design.md) - Detailed architecture and design decisions
