"""
Credential database verification fixture for integration tests.

Provides direct PostgreSQL access to verify credential records in the
user_credentials table, independent of the API layer.
"""

import logging

import psycopg2
import pytest

logger = logging.getLogger(__name__)

_SELECT_CREDENTIAL = """
SELECT username, access_key,
       pgp_sym_decrypt(secret_key, %(enc_key)s) AS secret_key,
       created_at, updated_at
  FROM user_credentials
 WHERE username = %(username)s;
"""

_DELETE_CREDENTIAL = """
DELETE FROM user_credentials WHERE username = %(username)s;
"""


class CredentialDBVerifier:
    """Direct PostgreSQL access for verifying credential records."""

    def __init__(self, conninfo: str, encryption_key: str):
        self._conninfo = conninfo
        self._encryption_key = encryption_key

    def get_credential_record(self, username: str) -> dict | None:
        """
        Fetch the credential record for a user directly from PostgreSQL.

        Returns:
            dict with keys: username, access_key, secret_key, created_at, updated_at
            None if no record exists for this user.
        """
        with psycopg2.connect(self._conninfo) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    _SELECT_CREDENTIAL,
                    {"username": username, "enc_key": self._encryption_key},
                )
                row = cur.fetchone()

        if row is None:
            return None

        return {
            "username": row[0],
            "access_key": row[1],
            "secret_key": row[2],
            "created_at": row[3],
            "updated_at": row[4],
        }

    def credential_exists(self, username: str) -> bool:
        """Check if a credential record exists for the user."""
        return self.get_credential_record(username) is not None

    def delete_credential(self, username: str) -> None:
        """Delete a credential record directly (for test cleanup)."""
        with psycopg2.connect(self._conninfo) as conn:
            with conn.cursor() as cur:
                cur.execute(_DELETE_CREDENTIAL, {"username": username})
            conn.commit()


@pytest.fixture(scope="session")
def credential_db(test_config) -> CredentialDBVerifier:
    """
    Session-scoped fixture providing direct DB access for credential verification.

    Skips if PostgreSQL is not reachable.
    """
    conninfo = (
        f"host={test_config['db_host']} "
        f"port={test_config['db_port']} "
        f"dbname={test_config['db_name']} "
        f"user={test_config['db_user']} "
        f"password={test_config['db_password']}"
    )
    encryption_key = test_config["db_encryption_key"]

    try:
        verifier = CredentialDBVerifier(conninfo, encryption_key)
        # Verify connection works
        with psycopg2.connect(conninfo) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        logger.info("CredentialDBVerifier connected to PostgreSQL")
        return verifier
    except Exception as e:
        pytest.skip(f"PostgreSQL not available for credential verification: {e}")
