# Ceph migration TODOs

## Remove __init__.py files from tests/s3/

The `tests/` tree has `__init__.py` files only because
`tests/minio/managers/` and `tests/s3/managers` have the same test files. Without the
`__init__.py` files, pytest cannot distinguish the two modules and raises an
import mismatch error.

Once `src/minio/` and `tests/minio/` are deleted, remove all of those
`__init__.py` files so `tests/` is consistent with the rest of the codebase.

## Remove policy_name from GroupModel and PolicyCreator

Once the MinIO code (`src/minio/`) is deleted:

- Remove `policy_name` from `GroupModel` (`src/s3/models/group.py`) — it was populated
  by the MinIO group manager and exposed in the API. The Ceph group manager does not
  populate it and the field has been removed from API responses.
- Remove `_generate_policy_name` from `PolicyCreator` (`src/s3/core/policy_creator.py`)
  and the `policy_name` field it populates in `build()` — only called from the MinIO
  policy manager (`src/minio/managers/policy_manager.py`), not used anywhere in
  the Ceph managers. `PolicyCreator` is a document builder and should not own IAM naming;
  `build()` should return a `PolicyDocument` (or accept the name as a constructor
  parameter), and `PolicyManager._create_policy_model` should set the name via
  `_policy_name_for` as it already does.
  - This also means `validate_policy_name` in `src/s3/utils/validators.py` can be
    removed (it is only called from `_generate_policy_name`) along with
    `DATA_GOVERNANCE_POLICY_PREFIXES` and the individual prefix constants
    (`USER_HOME_POLICY_PREFIX`, `USER_SYSTEM_POLICY_PREFIX`, `GROUP_POLICY_PREFIX`).
    Note: `PolicyModel` has its own inline `validate_policy_name` field validator that
    should be kept.
