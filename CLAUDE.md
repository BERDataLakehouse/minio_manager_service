# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The MinIO Manager Service is a centralized FastAPI-based microservice that programmatically manages MinIO users, groups, and policies for data governance within the BERDL platform. It integrates with KBase authentication and provides RESTful APIs for dynamic credential management and policy enforcement without requiring changes to Spark application code.

## Architecture

### Core Components

**FastAPI Application** (`src/main.py`):
- Main application entry point with route registration
- Health checks and middleware configuration
- CORS and error handling setup

**Service Layer** (`src/service/`):
- Business logic for MinIO user, group, and policy management
- KBase authentication integration
- Policy lifecycle management (Create, Read, Update, Delete)

**MinIO Operations** (`src/minio/`):
- Direct MinIO admin client integration
- User and policy CRUD operations
- Bucket and path management utilities

**API Routes** (`src/routes/`):
- RESTful endpoints for user management
- Group management and sharing operations
- Administrative endpoints for system management

### Key Features

**Dynamic Credential Management**:
- Issue temporary MinIO credentials on demand
- Automatic user credential rotation
- Scoped access keys for user namespaces

**Policy Enforcement**:
- Per-user home path creation and policy assignment
- Group-based sharing with inherited permissions
- Path-level access control for data governance

**KBase Integration**:
- Token-based authentication via KBase Auth Server
- Role-based access control with configurable required roles
- User identity resolution and validation
- Seamless integration with JupyterHub sessions

## Development Commands

### Python Package Management
```bash
# Install dependencies
uv sync --locked

# Install with dev dependencies
uv sync --group dev

# Run tests
PYTHONPATH=. uv run pytest tests

# Run tests with coverage
PYTHONPATH=. uv run pytest --cov=src tests/

# Run specific test file
PYTHONPATH=. uv run pytest tests/test_specific.py -v
```

### Code Quality
```bash
# Format code (via pyproject.toml configuration)
ruff format .

# Lint code
ruff check .

# Fix auto-fixable issues
ruff check . --fix
```

### Docker Operations
```bash
# Build image
docker build -t minio-manager-service .

# Run with docker-compose
docker compose up -d

# View logs
docker compose logs -f minio-manager-service
```

### Local Development
```bash
# Run service locally (requires environment variables)
PYTHONPATH=. uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

# Run with specific configuration
PYTHONPATH=. uv run python -m uvicorn src.main:app --reload
```

## Environment Configuration

### Required Environment Variables

**MinIO Configuration**:
- `MINIO_ENDPOINT`: MinIO server endpoint URL
- `MINIO_ROOT_USER`: MinIO admin access key
- `MINIO_ROOT_PASSWORD`: MinIO admin secret key
- `MINIO_SECURE`: Use HTTPS for MinIO connections (true/false)

**KBase Authentication**:
- `KBASE_AUTH_URL`: KBase authentication service URL
- `KBASE_ADMIN_ROLES`: Comma-separated list of KBase roles with full admin access (default: `KBASE_ADMIN`)
- `KBASE_REQUIRED_ROLES`: Comma-separated list of KBase roles required to authenticate. If not set, all authenticated users can access the service

**Service Configuration**:
- `REDIS_URL`: Redis connection string for caching (optional)
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

## API Endpoints

### User Management
- `GET /users/{user}`: Get user info and current policy
- `POST /users/{user}`: Create or rotate user credentials and policy
- `POST /users/{user}/share`: Grant path-level access between users/groups
- `POST /users/{user}/unshare`: Revoke path-level access

### Group Management
- `GET /groups/{group}`: List group members and policy
- `POST /groups/{group}`: Create or update group policy

### Administrative
- `GET /admin/users`: List all users
- `GET /admin/groups`: List all groups
- `DELETE /admin/users/{user}`: Delete user
- `DELETE /admin/groups/{group}`: Delete group

### Health and Status
- `GET /health`: Service health check
- `GET /docs`: API documentation (Swagger UI)

## Data Governance Model

### User Namespace Structure
```
s3a://cdm-lake/users-general-warehouse/{user_name}/   # General data files
s3a://cdm-lake/users-sql-warehouse/{user_name}/       # Spark SQL warehouse
```

### Group Namespace Structure
```
s3a://cdm-lake/groups-general-warehouse/{group_name}/ # Shared group data
```

### Policy Inheritance
1. **User Policies**: Direct access to user's home directories
2. **Group Policies**: Inherited access to group shared directories
3. **Shared Policies**: Temporary access to specifically shared paths

## Integration Points

### With JupyterHub
- Called automatically on user login for credential issuance
- Provides MinIO credentials for Spark session configuration
- Manages user workspace initialization

### With Apache Spark
- Credentials injected into Spark configuration at runtime
- Transparent S3A filesystem access with policy enforcement
- SQL warehouse directory automatically configured per user

### With KBase Authentication
- Validates user tokens against KBase Auth Server
- Resolves user identity for policy assignment
- Maintains session-based authentication flow

## Testing

### Unit Tests
- Located in `tests/` directory
- Uses pytest framework with asyncio support
- Covers service logic, API endpoints, and MinIO operations

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end API testing
- **Mock Tests**: External service dependency mocking

## Security Considerations

- Service holds only MinIO root admin credentials
- User credentials are generated transiently and not stored
- KBase token validation for all authenticated endpoints
- Role-based authentication - only users with required KBase roles can access the service
- Policy-based access control at MinIO layer
- Audit logging for all administrative operations

## Troubleshooting

### Common Issues
1. **MinIO Connection Failures**: Verify MINIO_ENDPOINT and credentials
2. **Authentication Errors**: Check KBase Auth URL and token validity
3. **Policy Creation Failures**: Ensure MinIO admin permissions
4. **Redis Connection Issues**: Verify Redis URL and service availability

### Debugging
- Enable DEBUG log level for detailed operation logging
- Check MinIO server logs for policy application issues
- Validate KBase token via direct API calls
- Use `/health` endpoint to verify service dependencies

## Future Enhancements

Based on design documentation:
1. **Enhanced Sharing**: More granular path-level sharing controls
2. **Audit Logging**: Comprehensive operation audit trail
3. **Policy Templates**: Predefined policy sets for common use cases
4. **Bulk Operations**: Batch user/group management capabilities
5. **Monitoring**: Metrics and alerting for service health

This service enables seamless data governance and access control within the BERDL platform while maintaining security and simplifying user experience.