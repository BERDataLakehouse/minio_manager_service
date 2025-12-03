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
- Rotate credentials on each request for enhanced security
- Assign per-user home directories:
  - `s3a://cdm-lake/users-general-warehouse/{username}/` - General data storage
  - `s3a://cdm-lake/users-sql-warehouse/{username}/` - Spark SQL warehouse

### Group Management
- Create and manage named groups (e.g., `KBase`, `BER`, `CDM_Science`)
- Assign users to groups with inherited permissions
- Share group workspace: `s3a://cdm-lake/groups-general-warehouse/{groupname}/`

### Data Sharing
- Grant/revoke path-level access between users and groups
- Fine-grained permissions: read-only or read-write
- Automatic policy updates without service restarts

### Security
- KBase authentication with role-based access control
- User credentials generated transiently (not stored)
- Service holds only MinIO root credentials
- Distributed locking via Redis for concurrent operations

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


## JupyterHub Integration

The service integrates seamlessly with JupyterHub:

1. **On user login**: JupyterHub calls `/credentials/` endpoint
2. **Credentials issued**: Service creates user (if needed) and returns fresh credentials
3. **Spark configured**: Credentials injected into Spark session configuration
4. **Transparent access**: Spark jobs access MinIO with proper permissions

Users can then use MinIO credentials to:
- Access their data via Spark (automatic)
- Log into MinIO Console for data management
- Share data with other users/groups via API

## Testing

```bash
# Install dependencies
uv sync --locked

# Run all tests
PYTHONPATH=. uv run pytest tests

# Run with coverage
PYTHONPATH=. uv run pytest --cov=src tests/

# Run specific tests
PYTHONPATH=. uv run pytest tests/routes/test_credentials.py -v
```

## Documentation

- [Design Document](docs/design.md) - Detailed architecture and design decisions
