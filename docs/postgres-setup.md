# PostgreSQL Setup for MMS Credential Store

This document covers how to set up the MMS credential database in each environment's PostgreSQL pod, and how to verify it's working.

## Environment Reference

| Environment | Postgres Pod | DB Host (from MMS) | DB Password |
|-------------|-------------|---------------------|-------------|
| Local dev | `minio_manager_service-postgres-1` | `postgres` | `mmspassword` |
| Dev (k8s) | `postgres-0` in `dev` namespace | `postgres.dev` | See `mms-env` ConfigMap |
| Prod (k8s) | `postgres-0` in `prod` namespace | `postgres.prod` | See `mms-env` ConfigMap |

## Setup Steps

### 1. Connect to the Postgres Pod

**Local docker-compose** (handled automatically by `init-mms-db.sh`):
```bash
docker exec -it minio_manager_service-postgres-1 psql -U hive
```

**Dev / Stage / Prod (via Rancher 2 UI):**
1. Open Rancher 2 UI
2. Navigate to the target namespace (`dev`, `stage`, or `prod`)
3. Find the `postgres-0` pod and click **Execute Shell**
4. In the shell, run:
```bash
psql -U postgres
```

### 2. Create the MMS Database, User, and Extension

Run these SQL commands as the `postgres` superuser.

**Important:** Run each command one at a time. Do NOT paste them all at once — `\c mms` will cause psql to misinterpret subsequent lines as connection parameters.

```sql
CREATE DATABASE mms;
```

```sql
CREATE USER mms WITH PASSWORD 'PASSWORD_FROM_CONFIGMAP';
```

Passwords per environment:
- **Dev:** `xbSw3+1IWyddalSQDOtDExv/cJiD9y9c`
- **Stage:** `iuIvmVZasGO7wPUh9g+JNGRmoaVrFjmw`
- **Prod:** `ASjI4AkETEodLndHQFp6U8SS59mCLKdQ`

```sql
GRANT ALL PRIVILEGES ON DATABASE mms TO mms;
```

Switch to the mms database (wait for `mms=#` prompt before continuing):

```sql
\c mms
```

Then install pgcrypto and grant access:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

```sql
GRANT ALL ON SCHEMA public TO mms;
```

### 3. Verify Setup

Still connected as superuser, verify everything is in place:

```sql
-- Verify database exists
\l mms

-- Verify user exists
\du mms

-- Verify pgcrypto is installed (CRITICAL - service will fail without this)
\c mms
SELECT * FROM pg_extension WHERE extname = 'pgcrypto';

-- Verify mms user can connect
-- Exit and reconnect as mms:
\q
```

Then reconnect as the `mms` user:

```bash
# Dev
kubectl exec -it postgres-0 -n dev -- psql -U mms -d mms

# Prod
kubectl exec -it postgres-0 -n prod -- psql -U mms -d mms
```

## Verifying the Credential Store is Working

After the MMS service starts and users request credentials, you can verify DB records directly.

### Connect to the MMS Database

```bash
# Dev
kubectl exec -it postgres-0 -n dev -- psql -U mms -d mms

# Prod
kubectl exec -it postgres-0 -n prod -- psql -U mms -d mms
```

### Common Queries

```sql
-- Check if the table was created (MMS creates it on startup)
\dt user_credentials

-- Count all credential records
SELECT count(*) FROM user_credentials;

-- List all cached users (without secrets)
SELECT username, access_key, created_at, updated_at
  FROM user_credentials
 ORDER BY updated_at DESC;

-- Check a specific user's record (without decrypting)
SELECT username, access_key, created_at, updated_at
  FROM user_credentials
 WHERE username = 'tgu2';

-- Decrypt and view a specific user's secret key
-- (requires the encryption key from the ConfigMap)
-- DEV:
SELECT username, access_key,
       pgp_sym_decrypt(secret_key, 'W+A9VGAakHs+7ZD3M45BmwkdMTiaZKobBEPnBhUTeV0=') AS secret_key,
       created_at, updated_at
  FROM user_credentials
 WHERE username = 'tgu2';

-- Verify encryption is actually working (raw bytes should NOT be readable)
SELECT username, secret_key FROM user_credentials WHERE username = 'tgu2';
-- ^ This should show binary gibberish, NOT plaintext

-- Check when credentials were last rotated
SELECT username, updated_at,
       now() - updated_at AS age
  FROM user_credentials
 ORDER BY updated_at DESC;
```

### Verifying End-to-End

1. **Trigger credential creation** — call the API:
   ```bash
   curl -H "Authorization: Bearer $KBASE_TOKEN" https://minio.dev.berdl.kbase.us/mms/credentials/
   ```

2. **Check the DB record appeared**:
   ```sql
   SELECT username, access_key, created_at FROM user_credentials ORDER BY created_at DESC LIMIT 5;
   ```

3. **Trigger a rotation**:
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://minio.dev.berdl.kbase.us/mms/management/users/tgu3/rotate-credentials
   ```

4. **Verify the DB record updated**:
   ```sql
   SELECT username, access_key, updated_at FROM user_credentials WHERE username = 'tgu3';
   -- updated_at should reflect the rotation time
   ```

5. **Verify deletion cleanup**:
   ```bash
   curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://minio.dev.berdl.kbase.us/mms/management/users/testuser123
   ```
   ```sql
   SELECT * FROM user_credentials WHERE username = 'testuser123';
   -- Should return 0 rows
   ```

## Troubleshooting

### "function pgp_sym_encrypt does not exist"
The pgcrypto extension is not installed. Connect as superuser and run:
```sql
\c mms
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

### "FATAL: password authentication failed for user mms"
The password in the ConfigMap doesn't match what was set in PostgreSQL. Reset it:
```sql
-- As superuser:
ALTER USER mms WITH PASSWORD 'the-password-from-configmap';
```

### "FATAL: database mms does not exist"
Run the full setup steps above — the database hasn't been created yet.

### Table exists but is empty
This is expected if no one has called `GET /credentials/` yet. The management API (`POST /management/users/`) creates MinIO users but does NOT create credential records. Records are only created when credentials are requested via the `/credentials/` endpoint.

### MMS service fails to start with "pgcrypto extension is not installed"
The service checks for pgcrypto at startup. Install it as described above, then restart the MMS pod:
```bash
kubectl rollout restart deployment mms -n dev
```
