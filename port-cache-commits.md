# Port commits from feature/cache-list-tenants-and-get-my-groups

Commits from PR #81 (branch deleted) that need porting from `src/minio` to `src/s3`:

| Hash | Message |
|---|---|
| `581897c` | perf: rewrite get_user_groups to use 'mc admin user info --json' |
| `0c12cbe` | perf: parallelize per-tenant membership reads in list_tenants |
| `7df478e` | feat(cache): add SingleFlightTTLCache utility |
| `078afff` | perf(GroupManager): add SingleFlightTTLCache for membership and group list |
| `f454d9f` | perf(TenantMetadataStore): add SingleFlightTTLCache for read methods |
| `b788a54` | perf(GroupManager): drop redundant resource_exists in _fetch_group_members |
| `f063c49` | run formatter |
| `60440df` | address minio get_group error |
| `1d639cf` | add additional test coverage |
| `a77452b` | unify TTL |
