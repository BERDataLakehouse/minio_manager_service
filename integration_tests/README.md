# Integration Tests for MinIO Manager Service

## Overview

This test suite is designed for **parallel-safe** execution with complete test isolation. It covers 80 tests across management, sharing, locking, workspaces, security, and Polaris synchronization.

---

## Prerequisites

Before running the tests, ensure you have:

1. **Docker** and **Docker Compose** installed
2. **Python 3.11+** with pip
3. **Valid KBase tokens** for test users

---

## Setup

### Step 1: Start the Services

```bash
cd /Users/tgu/Development/BERDL/minio_manager_service/integration_tests
docker compose down && docker compose up -d --build
```

### Step 2: Configure Environment

Copy the environment file:

```bash
cd integration_tests
cp ../API_tests/.env .env
```

Or create `.env` with these variables:

```bash
# Required
ADMIN_KBASE_TOKEN=your_admin_token_here   # tgu2 admin token
KBASE_TOKEN=your_user_token_here          # tgu3 user token

# Optional (have defaults)
API_BASE_URL=http://localhost:8010
MINIO_ENDPOINT=http://localhost:9012
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD=minio123
REDIS_URL=redis://localhost:6389

# PostgreSQL credential store (for DB verification tests)
MMS_DB_HOST=localhost
MMS_DB_PORT=5442
MMS_DB_NAME=mms
MMS_DB_USER=mms
MMS_DB_PASSWORD=mmspassword
MMS_DB_ENCRYPTION_KEY=change-me-in-prod

# Polaris (Optional, tests will skip if not set)
POLARIS_CATALOG_URI=http://localhost:8181/api/catalog
POLARIS_CREDENTIAL=root:secret
```

### Step 3: Install Dependencies

```bash
pip install pytest pytest-xdist httpx python-dotenv boto3 redis requests psycopg2-binary
```

### Step 4: Set Up Test Prerequisites

After container restarts, you need to provision the required test users and groups:

```bash
python ensure_test_prerequisites.py
```

This creates:
- **`tgu2`** - Admin user (ADMIN_KBASE_TOKEN owner)
- **`tgu3`** - Regular user (KBASE_TOKEN owner)

---

## Running Tests

### Recommended: Use the Test Runner Script

The test runner restarts Docker containers before each test group for a clean environment:

```bash
cd integration_tests

# Run all test groups (restarts Docker before each)
./run_tests.sh

# Run a specific test group only
./run_tests.sh management
./run_tests.sh sharing
./run_tests.sh workspaces
./run_tests.sh security
./run_tests.sh locking
./run_tests.sh polaris
```

### Run All Tests Manually

```bash
cd integration_tests
docker compose down && docker compose up -d --build
python ensure_test_prerequisites.py && pytest -n auto
```

### Run by Category

```bash
# Management tests (user/group CRUD)
pytest tests/management/ -n auto

# Sharing tests (access sharing, functional verification)
pytest tests/sharing/ -n auto

# Security tests (auth, input validation)
pytest tests/security/ -n auto

# Workspace tests (info, credentials)
pytest tests/workspaces/ -n auto

# Polaris tests (lifecycle sync)
pytest tests/management/test_polaris.py -n auto

# Locking tests (run serially)
pytest tests/locking/ -m serial
```

### Other Options

```bash
# Smoke tests only (quick sanity check)
pytest -m smoke -n auto

# Exclude serial tests for full parallel
pytest -m "not serial" -n auto

# Verbose with short traceback
pytest -v --tb=short
```

### Run Individual Tests

```bash
# Run a specific test file
pytest tests/test_health.py -v

# Run a specific test class
pytest tests/security/test_input_validation.py::TestPathTraversalPrevention -v

# Run a specific test method
pytest tests/security/test_input_validation.py::TestPathTraversalPrevention::test_share_path_traversal_blocked -v

# Run multiple specific tests
pytest tests/test_health.py::TestHealthCheck::test_health_endpoint tests/security/test_auth.py::TestInvalidTokenRejected::test_invalid_token_rejected -v
```

---

## Test Coverage

| Category | Tests | Description |
|----------|-------|-------------|
| **Management** | 17 | User/group CRUD, credential rotation, DB cleanup on delete |
| **Sharing** | 12 | Access sharing + functional file verification |
| **Security** | 21 | Auth requirements, input validation, injection prevention |
| **Workspaces** | 15 | Workspace info, credentials, DB persistence, concurrent ops |
| **Locking** | 5 | Distributed Redis locking |
| **Polaris** | 8 | End-to-end MinIO/Polaris lifecycle synchronization |
| **Health** | 2 | API health checks |
| **Total** | **80** | |

---

## Test Structure

```
integration_tests/
├── conftest.py           # Root fixtures
├── pytest.ini            # Configuration
├── .env                  # Environment variables (create from template)
│
├── fixtures/             # Reusable fixtures
│   ├── auth.py           # api_client, admin_headers, user_headers
│   ├── users.py          # temp_user, temp_user_pair, temp_users_factory
│   ├── groups.py         # temp_group, temp_group_with_members
│   ├── verification.py   # minio_verifier for state verification
│   ├── credential_db.py  # credential_db for direct PostgreSQL verification
│   └── polaris_verification.py # polaris_verifier for Polaris state
│
├── utils/                # Utility modules
│   ├── unique.py         # UUID generators (unique_username, unique_group_name)
│   ├── paths.py          # S3 path builders (user_table_path)
│   ├── cleanup.py        # Safe deletion helpers
│   └── minio_client.py   # Direct MinIO file operations
│
└── tests/
    ├── management/       # test_users.py, test_groups.py, test_polaris.py
    ├── sharing/          # test_share_read.py, test_functional_access.py
    ├── locking/          # test_file_locks.py
    ├── workspaces/       # test_workspace_info.py, test_credentials.py
    └── security/         # test_auth.py, test_input_validation.py
```

---

## Key Features

### Parallel-Safe Execution

- All resources use **UUID-based naming**: `testuser_a1b2c3d4`
- No hardcoded usernames or group names
- Tests can run simultaneously without interference

### Automatic Cleanup

Fixtures use `try/finally` to ensure cleanup:

```python
@pytest.fixture
def temp_user(api_client, admin_headers):
    username = unique_username()
    # Create user...
    yield user_data
    # Always cleanup, even on failure
    safe_delete_user(api_client, username, admin_headers)
```

### Functional Access Verification

Sharing tests verify **actual file access**, not just policy updates:

```python
def test_recipient_can_read_file_after_share(minio_files, temp_user_pair):
    # Create file → Share → Recipient actually reads it
    content = minio_files.read_as_user(bucket, key, recipient_creds)
    assert content == expected_content
```

---

## Troubleshooting

### Connection Refused

```
httpx.ConnectError: [Errno 61] Connection refused
```

**Solution**: Start the services: `docker compose up -d`

### Tests Skipped

```
67 skipped
```

**Solution**: Set tokens in `.env`:
- `ADMIN_KBASE_TOKEN` - Required for admin operations
- `KBASE_TOKEN` - Required for user operations

### Import Errors

```
ImportError: No module named 'utils'
```

**Solution**: Run from `integration_tests/` directory, not the parent.

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_BASE_URL` | No | `http://localhost:8010` | API endpoint |
| `ADMIN_KBASE_TOKEN` | **Yes** | - | Admin token (tgu2) |
| `KBASE_TOKEN` | **Yes** | - | User token (tgu3) |
| `MINIO_ENDPOINT` | No | `http://localhost:9012` | MinIO endpoint |
| `MINIO_ROOT_USER` | No | `minio` | MinIO root user |
| `MINIO_ROOT_PASSWORD` | No | `minio123` | MinIO root password |
| `REDIS_URL` | No | `redis://localhost:6389` | Redis for locking tests |
| `MMS_DB_HOST` | No | `localhost` | PostgreSQL host for credential DB verification |
| `MMS_DB_PORT` | No | `5442` | PostgreSQL port (mapped from container 5432) |
| `MMS_DB_NAME` | No | `mms` | PostgreSQL database name |
| `MMS_DB_USER` | No | `mms` | PostgreSQL user |
| `MMS_DB_PASSWORD` | No | `mmspassword` | PostgreSQL password |
| `MMS_DB_ENCRYPTION_KEY` | No | `change-me-in-prod` | pgcrypto encryption key for credential store |
| `POLARIS_CATALOG_URI` | No | - | Polaris API base URL for sync tests |
| `POLARIS_CREDENTIAL` | No | - | Polaris root config (client_id:secret) |
