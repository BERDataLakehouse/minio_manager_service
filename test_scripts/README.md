# test_scripts

Manual integration tests that run against live external services (Ceph, MinIO, Redis,
Postgres). These complement the unit tests in `tests/`, which mock all external
dependencies.

Use these scripts when you need to verify behaviour against a real service — for example,
after a dependency upgrade, when debugging a production issue, or when validating that a
new client implementation works correctly against the actual API.

## Prerequisites

Start the full stack with:

```bash
docker compose up -d
```

## Scripts

### `s3_iam_integration.py`

Exercises every method of `S3IAMClient` against the Ceph RadosGW instance defined in
`docker-compose.yml`. Covers user and group lifecycle (create, exists, list, delete),
inline policy round-trips, access key rotation, the `exists_ok` / `except_if_absent`
edge cases, and S3 data-plane policy enforcement (PUT/GET allowed and denied paths).

```bash
PYTHONPATH=src uv run python test_scripts/s3_iam_integration.py
```

### `s3_client_integration.py`

Exercises `S3Client` against the CEPH instance defined in `docker-compose.yml`.
Note: MinIO raises on duplicate bucket creation; Ceph silently succeeds.
Currently covers `create_bucket` (including `exists_ok` behaviour).
See the TODO at the top of the file for methods still to be covered.

```bash
PYTHONPATH=src uv run python test_scripts/s3_client_integration.py
```

### `group_manager_integration.py`

Exercises the full public API of `GroupManager` against the Ceph RadosGW and S3
instances defined in `docker-compose.yml`. Covers group lifecycle (`create_group`,
`group_exists`, `list_groups`, `delete_group`), membership management
(`add/remove_user_to/from_group`, `get_group_members`, `get_group_info`,
`is_user_in_group`, `get_user_groups`), and idempotency of `create_group`.

```bash
PYTHONPATH=src uv run python test_scripts/group_manager_integration.py
```

### `user_manager_integration.py`

Exercises the full public API of `UserManager` against the Ceph RadosGW, S3, and Redis
instances defined in `docker-compose.yml`. Covers user lifecycle (`create_user`, `get_user`,
`list_users`, `delete_user`, `user_exists`), credential rotation
(`get_or_rotate_user_credentials`), policy inspection (`get_user_policies`,
`get_user_accessible_paths`), and path ownership checks (`can_user_share_path`).

```bash
PYTHONPATH=src uv run python test_scripts/user_manager_integration.py
```

### `policy_manager_integration.py`

Exercises the full public API of `PolicyManager` against the Ceph RadosGW and Redis
instances defined in `docker-compose.yml`. Covers user and group policy lifecycle
(`ensure_*`, `get_*`, `regenerate_*`), pure policy manipulation (`add/remove_path_access_to_policy`,
`get_accessible_paths_from_policy`), and the distributed-lock read-modify-write path
(`add/remove_path_access_for_target`).

```bash
PYTHONPATH=src uv run python test_scripts/policy_manager_integration.py
```
