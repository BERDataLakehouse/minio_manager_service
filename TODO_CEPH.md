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

## Update the README

Update the main `README.md` to document:

- The switch from MinIO MC CLI to Ceph RadosGW IAM API
- The `S3IAMClient` and its configuration (endpoint, credentials, path prefix)
- Required environment variables for the IAM client
- The inline policy model used in Ceph (policy names: `home`, `system` for users;
  `group` for groups) and how it differs from MinIO's named managed policies
