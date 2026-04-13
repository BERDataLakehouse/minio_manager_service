# Ceph migration TODOs

## Remove __init__.py files from tests/s3/

The `tests/` tree has `__init__.py` files only because
`tests/minio/managers/` and `tests/s3/managers` have the same test files. Without the
`__init__.py` files, pytest cannot distinguish the two modules and raises an
import mismatch error.

Once `src/minio/` and `tests/minio/` are deleted, remove all of those
`__init__.py` files so `tests/` is consistent with the rest of the codebase.

## Remove policy_name from PolicyModel and GroupModel

Once the MinIO code (`src/minio/`) is deleted:

- Remove `policy_name` from `PolicyModel` (`src/s3/models/policy.py`) — it was only
  meaningful in MinIO where policies are globally-scoped named objects. In Ceph, inline
  policies have fixed names (`home`, `system`, `group`) local to the user/group.
- Remove `policy_name` from `GroupModel` (`src/s3/models/group.py`) — it was populated
  by the MinIO group manager and exposed in the API. The Ceph group manager does not
  populate it and the field has been removed from API responses.
- Remove `_generate_policy_name` from `PolicyCreator` (`src/s3/core/policy_creator.py`)
  and the `policy_name` field it populates in `build()` — only called from the MinIO
  policy manager (`src/minio/managers/policy_manager.py:1019`), not used anywhere in
  the Ceph managers.
  - This also means the validate policy name method can be removed as well as various
    exceptions throughout the code base cause by failed validation in policy creator
