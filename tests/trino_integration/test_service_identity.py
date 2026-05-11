"""Tests for the per-tenant Trino service identity orchestration.

Covers the happy-path provision/deprovision flow plus key invariants:
- the IAM and Polaris sides are both invoked with the right arguments
- credentials returned by Polaris are persisted in the credential store
- the IAM access keys are persisted in the s3 credential store
- deprovision is best-effort and continues past per-step failures
- a missing Polaris credential payload raises explicitly
"""

from unittest.mock import AsyncMock

import pytest

from credentials.polaris_store import PolarisCredentialRecord
from s3.models.user import UserModel
from service.exceptions import GroupOperationError, PolarisOperationError
from trino_integration.service_identity import (
    MAX_TRINO_TENANT_NAME_LENGTH,
    TrinoServiceIdentity,
    deprovision_tenant_trino_service,
    ensure_tenant_trino_service,
    provision_tenant_trino_service,
    service_user_name,
    tenant_alias,
    tenant_warehouse_name,
    validate_trino_tenant_name,
)


# === Helpers ===


def _make_user_model(svc_user: str) -> UserModel:
    return UserModel(
        username=svc_user,
        s3_access_key=svc_user,
        s3_secret_key="iam-secret-xyz",
        home_paths=[],
        groups=[],
        total_policies=0,
    )


@pytest.fixture
def deps():
    """Bundle of mocked dependencies for the orchestration functions.

    Each manager is an :class:`AsyncMock` so individual ``await`` calls don't
    explode. Callers customize specific attributes per-test.
    """
    user_manager = AsyncMock()
    user_manager.create_service_user = AsyncMock(
        return_value=_make_user_model("trino-globalusers-svc")
    )
    user_manager.delete_service_user = AsyncMock()
    user_manager.resource_exists = AsyncMock(return_value=True)

    group_manager = AsyncMock()
    group_manager.add_user_to_group = AsyncMock()
    group_manager.remove_user_from_group = AsyncMock()

    polaris_group_manager = AsyncMock()
    polaris_group_manager.add_user_to_group = AsyncMock()
    polaris_group_manager.remove_user_from_group = AsyncMock()

    polaris_user_manager = AsyncMock()
    polaris_user_manager.reset_credentials = AsyncMock(
        return_value={
            "credentials": {
                "clientId": "svc-client-id",
                "clientSecret": "svc-client-secret",
            }
        }
    )

    polaris_service = AsyncMock()
    polaris_service.delete_principal = AsyncMock()

    s3_credential_store = AsyncMock()
    s3_credential_store.get_credentials = AsyncMock(
        return_value=("trino-globalusers-svc", "cached-iam-secret")
    )
    s3_credential_store.store_credentials = AsyncMock()
    s3_credential_store.delete_credentials = AsyncMock()

    polaris_credential_store = AsyncMock()
    polaris_credential_store.get_credentials = AsyncMock(
        return_value=PolarisCredentialRecord(
            client_id="cached-client-id",
            client_secret="cached-client-secret",
            personal_catalog="tenant_globalusers",
        )
    )
    polaris_credential_store.store_credentials = AsyncMock()
    polaris_credential_store.delete_credentials = AsyncMock()

    return {
        "user_manager": user_manager,
        "group_manager": group_manager,
        "polaris_group_manager": polaris_group_manager,
        "polaris_user_manager": polaris_user_manager,
        "polaris_service": polaris_service,
        "s3_credential_store": s3_credential_store,
        "polaris_credential_store": polaris_credential_store,
    }


# === Naming helpers ===


class TestNamingHelpers:
    def test_service_user_name(self):
        assert service_user_name("globalusers") == "trino-globalusers-svc"

    def test_tenant_alias_lowercases_and_sanitizes(self):
        assert tenant_alias("GlobalUsers") == "globalusers"
        assert tenant_alias("Research-Team") == "research_team"

    def test_tenant_alias_strips_leading_trailing_underscores(self):
        assert tenant_alias("__weird__") == "weird"

    def test_tenant_warehouse_name(self):
        assert tenant_warehouse_name("globalusers") == "tenant_globalusers"

    def test_validate_trino_tenant_name_accepts_valid_name(self):
        assert validate_trino_tenant_name("globalusers") == "globalusers"

    def test_validate_trino_tenant_name_rejects_read_only_suffix(self):
        with pytest.raises(GroupOperationError, match="cannot end with 'ro'"):
            validate_trino_tenant_name("globalusersro")

    def test_validate_trino_tenant_name_rejects_names_that_make_long_service_user(
        self,
    ):
        with pytest.raises(GroupOperationError, match="at most"):
            validate_trino_tenant_name("a" * (MAX_TRINO_TENANT_NAME_LENGTH + 1))


# === provision_tenant_trino_service ===


class TestProvision:
    @pytest.mark.asyncio
    async def test_returns_service_identity(self, deps):
        identity = await provision_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        assert isinstance(identity, TrinoServiceIdentity)
        assert identity.tenant_alias == "globalusers"
        assert identity.iam_username == "trino-globalusers-svc"
        assert identity.s3_access_key == "trino-globalusers-svc"
        assert identity.s3_secret_key == "iam-secret-xyz"
        assert identity.polaris_principal == "trino-globalusers-svc"
        assert identity.polaris_client_id == "svc-client-id"
        assert identity.polaris_client_secret == "svc-client-secret"
        assert identity.polaris_warehouse == "tenant_globalusers"

    @pytest.mark.asyncio
    async def test_creates_iam_user_and_adds_to_ro_group(self, deps):
        await provision_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        deps["user_manager"].create_service_user.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["group_manager"].add_user_to_group.assert_awaited_once_with(
            "trino-globalusers-svc", "globalusersro"
        )

    @pytest.mark.asyncio
    async def test_polaris_side_uses_existing_add_to_group_helper(self, deps):
        """Critical invariant: we mirror the human-user route's flow by calling
        PolarisGroupManager.add_user_to_group, NOT extending ensure_tenant_catalog.
        """
        await provision_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        deps["polaris_group_manager"].add_user_to_group.assert_awaited_once_with(
            "trino-globalusers-svc", "globalusersro"
        )
        # We must reset credentials AFTER add_user_to_group has created the principal.
        deps["polaris_user_manager"].reset_credentials.assert_awaited_once_with(
            "trino-globalusers-svc"
        )

    @pytest.mark.asyncio
    async def test_persists_both_credential_sets(self, deps):
        await provision_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        deps["s3_credential_store"].store_credentials.assert_awaited_once_with(
            username="trino-globalusers-svc",
            access_key="trino-globalusers-svc",
            secret_key="iam-secret-xyz",
        )
        # personal_catalog field carries the tenant warehouse for service identities
        deps["polaris_credential_store"].store_credentials.assert_awaited_once_with(
            username="trino-globalusers-svc",
            client_id="svc-client-id",
            client_secret="svc-client-secret",
            personal_catalog="tenant_globalusers",
        )

    @pytest.mark.asyncio
    async def test_raises_when_polaris_returns_no_credentials(self, deps):
        """If Polaris reset returns a payload missing clientId/clientSecret, the
        provision must fail loudly so the caller (route layer) sees a 5xx."""
        deps["polaris_user_manager"].reset_credentials = AsyncMock(
            return_value={"credentials": {}}
        )
        with pytest.raises(PolarisOperationError):
            await provision_tenant_trino_service(
                "globalusers",
                **{k: v for k, v in deps.items() if k != "polaris_service"},
            )

    @pytest.mark.asyncio
    async def test_raises_when_polaris_omits_credentials_key(self, deps):
        deps["polaris_user_manager"].reset_credentials = AsyncMock(return_value={})
        with pytest.raises(PolarisOperationError):
            await provision_tenant_trino_service(
                "globalusers",
                **{k: v for k, v in deps.items() if k != "polaris_service"},
            )


class TestEnsure:
    @pytest.mark.asyncio
    async def test_cached_credentials_do_not_rotate(self, deps):
        identity = await ensure_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        assert identity.s3_secret_key == "cached-iam-secret"
        assert identity.polaris_client_id == "cached-client-id"
        assert identity.polaris_client_secret == "cached-client-secret"
        deps["user_manager"].create_service_user.assert_not_awaited()
        deps["polaris_user_manager"].reset_credentials.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_repairs_reader_bindings_even_when_credentials_cached(self, deps):
        await ensure_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        deps["group_manager"].add_user_to_group.assert_awaited_once_with(
            "trino-globalusers-svc", "globalusersro"
        )
        deps["polaris_group_manager"].add_user_to_group.assert_awaited_once_with(
            "trino-globalusers-svc", "globalusersro"
        )

    @pytest.mark.asyncio
    async def test_missing_s3_credentials_create_and_store_service_user(self, deps):
        deps["s3_credential_store"].get_credentials = AsyncMock(return_value=None)

        identity = await ensure_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        assert identity.s3_secret_key == "iam-secret-xyz"
        deps["user_manager"].create_service_user.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["s3_credential_store"].store_credentials.assert_awaited_once_with(
            username="trino-globalusers-svc",
            access_key="trino-globalusers-svc",
            secret_key="iam-secret-xyz",
        )

    @pytest.mark.asyncio
    async def test_missing_iam_user_rotates_and_stores_s3_credentials(self, deps):
        deps["user_manager"].resource_exists = AsyncMock(return_value=False)

        await ensure_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        deps["user_manager"].create_service_user.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["s3_credential_store"].store_credentials.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_missing_polaris_credentials_reset_and_store(self, deps):
        deps["polaris_credential_store"].get_credentials = AsyncMock(return_value=None)

        identity = await ensure_tenant_trino_service(
            "globalusers",
            **{k: v for k, v in deps.items() if k != "polaris_service"},
        )

        assert identity.polaris_client_id == "svc-client-id"
        deps["polaris_user_manager"].reset_credentials.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["polaris_credential_store"].store_credentials.assert_awaited_once_with(
            username="trino-globalusers-svc",
            client_id="svc-client-id",
            client_secret="svc-client-secret",
            personal_catalog="tenant_globalusers",
        )


# === deprovision_tenant_trino_service ===


class TestDeprovision:
    @pytest.mark.asyncio
    async def test_calls_all_teardown_steps(self, deps):
        # delete_principal is on polaris_service (not polaris_user_manager.delete_user)
        # because the latter would also drop the personal catalog the service
        # identity does not have.
        deprovision_deps = {
            "user_manager": deps["user_manager"],
            "group_manager": deps["group_manager"],
            "polaris_group_manager": deps["polaris_group_manager"],
            "polaris_service": deps["polaris_service"],
            "s3_credential_store": deps["s3_credential_store"],
            "polaris_credential_store": deps["polaris_credential_store"],
        }

        await deprovision_tenant_trino_service("globalusers", **deprovision_deps)

        deps["polaris_group_manager"].remove_user_from_group.assert_awaited_once_with(
            "trino-globalusers-svc", "globalusersro"
        )
        deps["polaris_service"].delete_principal.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["polaris_credential_store"].delete_credentials.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["group_manager"].remove_user_from_group.assert_awaited_once_with(
            "trino-globalusers-svc", "globalusersro"
        )
        deps["user_manager"].delete_service_user.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["s3_credential_store"].delete_credentials.assert_awaited_once_with(
            "trino-globalusers-svc"
        )

    @pytest.mark.asyncio
    async def test_continues_past_polaris_step_failures(self, deps):
        """If Polaris-side teardown errors (404 race, connectivity blip), the
        IAM-side teardown must still run so we don't leak the IAM service user."""
        deps["polaris_group_manager"].remove_user_from_group = AsyncMock(
            side_effect=Exception("Polaris 404 race")
        )
        deps["polaris_service"].delete_principal = AsyncMock(
            side_effect=Exception("Polaris connectivity blip")
        )

        deprovision_deps = {
            "user_manager": deps["user_manager"],
            "group_manager": deps["group_manager"],
            "polaris_group_manager": deps["polaris_group_manager"],
            "polaris_service": deps["polaris_service"],
            "s3_credential_store": deps["s3_credential_store"],
            "polaris_credential_store": deps["polaris_credential_store"],
        }

        # Must not raise.
        await deprovision_tenant_trino_service("globalusers", **deprovision_deps)

        # IAM-side teardown ran despite earlier failures.
        deps["user_manager"].delete_service_user.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
        deps["s3_credential_store"].delete_credentials.assert_awaited_once_with(
            "trino-globalusers-svc"
        )

    @pytest.mark.asyncio
    async def test_continues_past_iam_step_failures(self, deps):
        deps["user_manager"].delete_service_user = AsyncMock(
            side_effect=Exception("IAM error")
        )

        deprovision_deps = {
            "user_manager": deps["user_manager"],
            "group_manager": deps["group_manager"],
            "polaris_group_manager": deps["polaris_group_manager"],
            "polaris_service": deps["polaris_service"],
            "s3_credential_store": deps["s3_credential_store"],
            "polaris_credential_store": deps["polaris_credential_store"],
        }

        await deprovision_tenant_trino_service("globalusers", **deprovision_deps)

        # Credential purge still runs.
        deps["s3_credential_store"].delete_credentials.assert_awaited_once_with(
            "trino-globalusers-svc"
        )
