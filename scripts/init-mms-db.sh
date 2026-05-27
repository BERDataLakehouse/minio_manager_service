#!/bin/bash
set -e

# MMS database + pgcrypto.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE mms;
    CREATE USER mms WITH PASSWORD 'mmspassword';
    GRANT ALL PRIVILEGES ON DATABASE mms TO mms;
    \c mms
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    GRANT ALL ON SCHEMA public TO mms;
EOSQL

# PgBouncer auth scaffolding. Function lives in the `postgres` admin DB so
# PgBouncer's auth_dbname=postgres can reach it regardless of which target db
# the client asked for.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<-EOSQL
    CREATE ROLE pgbouncer_auth WITH LOGIN PASSWORD 'pgbouncer_auth_pw';
    CREATE ROLE pgbouncer_admin WITH LOGIN PASSWORD 'pgbouncer_admin_pw';
    CREATE ROLE pgbouncer_stats WITH LOGIN PASSWORD 'pgbouncer_stats_pw';

    CREATE SCHEMA pgbouncer_auth_schema AUTHORIZATION "$POSTGRES_USER";
    GRANT USAGE ON SCHEMA pgbouncer_auth_schema TO pgbouncer_auth;

    CREATE OR REPLACE FUNCTION pgbouncer_auth_schema.user_lookup(
      IN p_username text,
      OUT username  text,
      OUT password  text
    ) RETURNS record AS \$\$
    BEGIN
      SELECT usename, passwd
        INTO username, password
        FROM pg_catalog.pg_shadow
       WHERE usename = p_username;
      RETURN;
    END;
    \$\$ LANGUAGE plpgsql
       SECURITY DEFINER
       SET search_path = pg_catalog;

    REVOKE ALL ON FUNCTION pgbouncer_auth_schema.user_lookup(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION pgbouncer_auth_schema.user_lookup(text) TO pgbouncer_auth;

    -- Replication role + slot for the streaming standby.
    CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator_pw';
    SELECT pg_create_physical_replication_slot('mms_replica_slot');
EOSQL

# Allow the replica to connect for streaming replication. The default
# pg_hba.conf only permits replication from localhost; appending an entry
# for the docker network and reloading.
cat >> /var/lib/postgresql/data/pg_hba.conf <<'HBA'

# Streaming replication from postgres-replica.
host    replication    replicator    all    scram-sha-256
HBA
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -c "SELECT pg_reload_conf();"
