# src/minio — superseded

The code in this directory manages MinIO IAM operations (users, groups, policies) by
shelling out to the MinIO MC CLI (`mc`) as a subprocess.

It will be replaced by the implementation in `src/s3/`, which uses the standard S3/IAM
API via aiobotocore and targets Ceph RadosGW or any other S3 IAMs compatible system.
Note that this replacement is **not** compatible with MinIO: MinIO does not support
inline policies via the IAM API and exposes its own idiosyncratic admin API
(which is what the MC CLI wraps).

This directory is preserved to allow side-by-side comparison with the new implementation
and will be deleted once the migration is complete.
