# MinIO Manager Service

[![codecov](https://codecov.io/gh/BERDataLakehouse/minio_manager_service/branch/main/graph/badge.svg)](https://codecov.io/gh/BERDataLakehouse/minio_manager_service)

A centralized FastAPI-based microservice that manages MinIO users, groups, and policies for data governance within the BERDL platform. It provides dynamic credential management and policy enforcement for Spark applications without requiring code changes.

## Overview

The MinIO Manager Service enables:

- **Dynamic Credential Management**: Issue and rotate per-user MinIO credentials on demand
- **Automated Policy Enforcement**: Maintain user and group-level IAM policies with automatic updates
- **Data Governance**: Path-level access control with sharing capabilities between users and groups
- **Seamless Integration**: Zero-code changes for Spark applications; credentials injected at runtime

## Key Features

### User Management
- Auto-create MinIO users with unique access/secret key pairs
- Credentials cached in PostgreSQL and returned on subsequent requests until explicitly rotated via `POST /credentials/rotate`
- Assign per-user home directories:
  - `s3a://cdm-lake/users-general-warehouse/{username}/` - General data storage
  - `s3a://cdm-lake/users-sql-warehouse/{username}/` - Spark SQL warehouse

### Tenant Management
- Tenants are the primary organizational unit, built on top of MinIO groups
- Each tenant has metadata (display name, description, website, organization), members, and data stewards
- **Data stewards** can manage tenant membership and update metadata without being a full admin
- Members are assigned read-write or read-only access
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
- Create and manage named MinIO groups (the underlying primitive for tenants)
- Assign users to groups with inherited permissions
- Read-only groups via `{groupname}ro` convention
- Share group workspace: `s3a://cdm-lake/groups-general-warehouse/{groupname}/`

### Data Sharing
- Grant/revoke path-level access between users and groups
- Fine-grained permissions: read-only or read-write
- Automatic policy updates without service restarts

### Security
- KBase authentication with role-based access control
- User credentials encrypted at rest in PostgreSQL (pgcrypto)
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
# - API: http://localhost:8000/docs
# - MinIO Console: http://localhost:9003 (minio/minio123)
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MINIO_ENDPOINT` | Yes | - | MinIO server endpoint (e.g., `http://minio:9002`) |
| `MINIO_ROOT_USER` | Yes | - | MinIO root username |
| `MINIO_ROOT_PASSWORD` | Yes | - | MinIO root password |
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

The service integrates seamlessly with JupyterHub:

1. **On user login**: JupyterHub calls `/credentials/` endpoint
2. **Credentials issued**: Service creates user (if needed), caches credentials in PostgreSQL, and returns them
3. **Spark configured**: Credentials injected into Spark session configuration
4. **Transparent access**: Spark jobs access MinIO with proper permissions

Users can then use MinIO credentials to:
- Access their data via Spark (automatic)
- Log into MinIO Console for data management
- Share data with other users/groups via API

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
