"""Shared constants and helpers for Polaris integration."""

from typing import Tuple

# Subdirectory appended to SQL warehouse paths for Iceberg catalog storage.
# Each user/tenant catalog stores data under <warehouse_path>/<name>/iceberg/.
# This path has its own IAM statement separate from the u_{username}__* governed path.
ICEBERG_STORAGE_SUBDIRECTORY = "iceberg"


def normalize_group_name_for_polaris(group_name: str) -> Tuple[str, bool]:
    """Derive the base group name and read-only flag for Polaris operations.

    Read-only groups use the suffix "ro" (e.g., "kbasero" → base "kbase", is_ro=True).

    Returns:
        (base_group_name, is_read_only_group)
    """
    if group_name.endswith("ro"):
        return group_name[:-2], True
    return group_name, False
