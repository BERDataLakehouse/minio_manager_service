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
PYTHONPATH=. uv run python test_scripts/s3_iam_integration.py
```
