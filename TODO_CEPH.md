# Ceph migration TODOs

## Make path prefix a configuration item

The `path_prefix` parameter in `S3IAMClient` is currently hardcoded at instantiation time
in `app_state.py`. It should be promoted to a field in `S3Config` so that it is:

- Configurable per environment via the standard config mechanism
- Documented alongside the other S3/IAM connection settings

**Why this matters for migration:** when cutting over from MinIO to Ceph, setting a
non-default prefix (e.g. `/mms/`) scopes all service-managed IAM entities to that
path. This makes it straightforward to distinguish service-created users and groups from
any pre-existing entities on the Ceph cluster, and allows the two to coexist safely
during a staged migration. The prefix must be decided and set before any users or groups
are created in Ceph.

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

## Update the README

Update the main `README.md` to document:

- The switch from MinIO MC CLI to Ceph RadosGW IAM API
- The `S3IAMClient` and its configuration (endpoint, credentials, path prefix)
- Required environment variables for the IAM client
- The inline policy model used in Ceph (policy names: `home`, `system` for users;
  `group` for groups) and how it differs from MinIO's named managed policies
