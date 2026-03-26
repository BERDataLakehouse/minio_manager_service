#!/usr/bin/env python3
"""Backfill tenant_metadata rows for existing MinIO groups.

Usage (local, with env vars):
    MMS_DB_HOST=localhost MMS_DB_PORT=5432 MMS_DB_NAME=mms \
    MMS_DB_USER=mms MMS_DB_PASSWORD=secret \
    MINIO_ENDPOINT=localhost:9000 MINIO_ROOT_USER=admin MINIO_ROOT_PASSWORD=secret \
    python scripts/backfill_tenant_metadata.py [--dry-run]

Usage (inside minio-manager container):
    The scripts/ directory is included in the Docker image at /app/scripts/.
    All required env vars (MINIO_ENDPOINT, MINIO_ROOT_USER, MINIO_ROOT_PASSWORD,
    MMS_DB_*) are already set in the container.

    # Exec into the container:
    docker exec -it <container> bash

    # Then run from /app:
    uv run python scripts/backfill_tenant_metadata.py --dry-run   # preview changes
    uv run python scripts/backfill_tenant_metadata.py              # run for real

For each MinIO group that looks like a tenant (not in SYSTEM_GROUPS, not
ending in 'ro'), inserts a tenant_metadata row with ON CONFLICT DO NOTHING.
Safe to run multiple times.
"""

import argparse
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from psycopg.conninfo import make_conninfo
from psycopg_pool import AsyncConnectionPool

from src.minio.core.minio_client import MinIOClient
from src.minio.managers.group_manager import GroupManager
from src.minio.managers.tenant_manager import SYSTEM_GROUPS
from src.minio.models.minio_config import MinIOConfig

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_INSERT = """
INSERT INTO tenant_metadata (tenant_name, display_name, created_by, created_at, updated_at)
VALUES (%(tenant_name)s, %(tenant_name)s, 'backfill', now(), now())
ON CONFLICT (tenant_name) DO NOTHING;
"""


def _is_tenant_group(name: str) -> bool:
    return name not in SYSTEM_GROUPS and not name.endswith("ro")


async def main(dry_run: bool) -> None:
    config = MinIOConfig(
        endpoint=os.environ["MINIO_ENDPOINT"],
        access_key=os.environ["MINIO_ROOT_USER"],
        secret_key=os.environ["MINIO_ROOT_PASSWORD"],
    )
    minio_client = await MinIOClient.create(config)
    group_manager = GroupManager(minio_client, config)

    all_groups = await group_manager.list_resources()
    tenants = [g for g in all_groups if _is_tenant_group(g)]
    logger.info("Found %d tenant groups to backfill", len(tenants))

    if dry_run:
        for t in sorted(tenants):
            logger.info("  [dry-run] would insert: %s", t)
        await minio_client.close_session()
        return

    conninfo = make_conninfo(
        host=os.environ["MMS_DB_HOST"],
        port=int(os.environ.get("MMS_DB_PORT", "5432")),
        dbname=os.environ["MMS_DB_NAME"],
        user=os.environ["MMS_DB_USER"],
        password=os.environ["MMS_DB_PASSWORD"],
    )
    pool = AsyncConnectionPool(conninfo=conninfo, min_size=1, max_size=2, open=False)
    await pool.open()

    inserted = 0
    async with pool.connection() as conn:
        for t in sorted(tenants):
            cur = await conn.execute(_INSERT, {"tenant_name": t})
            if cur.rowcount > 0:
                inserted += 1
                logger.info("  inserted: %s", t)
            else:
                logger.info("  already exists: %s", t)
        await conn.commit()

    logger.info(
        "Backfill complete: %d inserted, %d already existed",
        inserted,
        len(tenants) - inserted,
    )

    await pool.close()
    await minio_client.close_session()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="List groups without inserting"
    )
    args = parser.parse_args()
    asyncio.run(main(args.dry_run))
