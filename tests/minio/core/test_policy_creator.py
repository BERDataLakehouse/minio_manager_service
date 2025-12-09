"""Comprehensive tests for the minio.core.policy_creator module."""

from unittest.mock import MagicMock

import pytest

from src.minio.core.policy_creator import (
    PolicyCreator,
    SYSTEM_RESOURCE_CONFIG,
    _POLICY_ACTION_TO_POLICY_SECTION,
)
from src.minio.models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyModel,
    PolicyPermissionLevel,
    PolicySectionType,
    PolicyStatement,
    PolicyType,
)
from src.service.exceptions import PolicyOperationError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_minio_config():
    """Create a mock MinIOConfig."""
    config = MagicMock()
    config.default_bucket = "data-lake"
    config.users_sql_warehouse_prefix = "users-sql-warehouse"
    config.users_general_warehouse_prefix = "users-general-warehouse"
    config.tenant_sql_warehouse_prefix = "tenant-sql-warehouse"
    config.tenant_general_warehouse_prefix = "tenant-general-warehouse"
    return config


@pytest.fixture
def user_home_creator(mock_minio_config):
    """Create a PolicyCreator for user home policy."""
    return PolicyCreator(
        policy_type=PolicyType.USER_HOME,
        target_name="testuser",
        config=mock_minio_config,
    )


@pytest.fixture
def user_system_creator(mock_minio_config):
    """Create a PolicyCreator for user system policy."""
    return PolicyCreator(
        policy_type=PolicyType.USER_SYSTEM,
        target_name="testuser",
        config=mock_minio_config,
    )


@pytest.fixture
def group_policy_creator(mock_minio_config):
    """Create a PolicyCreator for group policy."""
    return PolicyCreator(
        policy_type=PolicyType.GROUP_HOME,
        target_name="testgroup",
        config=mock_minio_config,
    )


@pytest.fixture
def group_read_only_policy_creator(mock_minio_config):
    """Create a PolicyCreator for group read-only policy."""
    return PolicyCreator(
        policy_type=PolicyType.GROUP_HOME_RO,
        target_name="testgroupro",
        config=mock_minio_config,
    )


# =============================================================================
# TEST INITIALIZATION
# =============================================================================


class TestPolicyCreatorInit:
    """Tests for PolicyCreator initialization."""

    def test_init_user_home_policy(self, mock_minio_config):
        """Test initialization for user home policy."""
        creator = PolicyCreator(
            policy_type=PolicyType.USER_HOME,
            target_name="testuser",
            config=mock_minio_config,
        )

        assert creator.policy_type == PolicyType.USER_HOME
        assert creator.target_name == "testuser"
        assert creator.config == mock_minio_config
        assert (
            creator.user_sql_warehouse_path
            == "s3a://data-lake/users-sql-warehouse/testuser"
        )
        assert (
            creator.user_general_warehouse_path
            == "s3a://data-lake/users-general-warehouse/testuser"
        )

    def test_init_user_system_policy(self, mock_minio_config):
        """Test initialization for user system policy."""
        creator = PolicyCreator(
            policy_type=PolicyType.USER_SYSTEM,
            target_name="testuser",
            config=mock_minio_config,
        )

        assert creator.policy_type == PolicyType.USER_SYSTEM
        assert creator.system_config == SYSTEM_RESOURCE_CONFIG

    def test_init_group_policy(self, mock_minio_config):
        """Test initialization for group policy."""
        creator = PolicyCreator(
            policy_type=PolicyType.GROUP_HOME,
            target_name="testgroup",
            config=mock_minio_config,
        )

        assert creator.policy_type == PolicyType.GROUP_HOME
        assert (
            creator.tenant_sql_warehouse_path
            == "s3a://data-lake/tenant-sql-warehouse/testgroup"
        )
        assert (
            creator.tenant_general_warehouse_path
            == "s3a://data-lake/tenant-general-warehouse/testgroup"
        )

    def test_init_group_read_only_policy(self, mock_minio_config):
        """Test initialization for group read-only policy."""
        creator = PolicyCreator(
            policy_type=PolicyType.GROUP_HOME_RO,
            target_name="testgroup",
            config=mock_minio_config,
        )

        assert creator.policy_type == PolicyType.GROUP_HOME_RO
        assert (
            creator.tenant_sql_warehouse_path
            == "s3a://data-lake/tenant-sql-warehouse/testgroup"
        )
        assert (
            creator.tenant_general_warehouse_path
            == "s3a://data-lake/tenant-general-warehouse/testgroup"
        )

    def test_init_sections_empty(self, user_home_creator):
        """Test sections are initialized empty."""
        sections = user_home_creator.get_sections()

        for section_type in PolicySectionType:
            assert section_type in sections
            assert sections[section_type] == []


# =============================================================================
# TEST GET SECTIONS
# =============================================================================


class TestGetSections:
    """Tests for get_sections method."""

    def test_get_sections_returns_copy(self, user_home_creator):
        """Test get_sections returns a copy, not the original."""
        sections1 = user_home_creator.get_sections()
        sections2 = user_home_creator.get_sections()

        # Should be equal but not the same object
        assert sections1 == sections2
        assert sections1 is not sections2

    def test_get_sections_all_types_present(self, user_home_creator):
        """Test all section types are present."""
        sections = user_home_creator.get_sections()

        expected_sections = [
            PolicySectionType.GLOBAL_PERMISSIONS,
            PolicySectionType.BUCKET_ACCESS,
            PolicySectionType.READ_PERMISSIONS,
            PolicySectionType.WRITE_PERMISSIONS,
            PolicySectionType.DELETE_PERMISSIONS,
        ]

        for section_type in expected_sections:
            assert section_type in sections


# =============================================================================
# TEST GENERATE POLICY NAME
# =============================================================================


class TestGeneratePolicyName:
    """Tests for _generate_policy_name method."""

    def test_generate_user_home_policy_name(self, user_home_creator):
        """Test generating user home policy name."""
        name = user_home_creator._generate_policy_name()
        assert name == "user-home-policy-testuser"

    def test_generate_user_system_policy_name(self, user_system_creator):
        """Test generating user system policy name."""
        name = user_system_creator._generate_policy_name()
        assert name == "user-system-policy-testuser"

    def test_generate_group_policy_name(self, group_policy_creator):
        """Test generating group policy name."""
        name = group_policy_creator._generate_policy_name()
        assert name == "group-policy-testgroup"

    def test_generate_group_read_only_policy_name(self, group_read_only_policy_creator):
        """Test generating group read-only policy name."""
        name = group_read_only_policy_creator._generate_policy_name()
        assert name == "group-policy-testgroup"

    def test_generate_policy_name_unknown_type(self, mock_minio_config):
        """Test generating policy name with unknown type raises error."""
        creator = PolicyCreator(
            policy_type=PolicyType.USER_HOME,
            target_name="testuser",
            config=mock_minio_config,
        )
        # Manually set invalid type
        creator.policy_type = "invalid"

        with pytest.raises(PolicyOperationError):
            creator._generate_policy_name()


# =============================================================================
# TEST CREATE DEFAULT POLICY
# =============================================================================


class TestCreateDefaultPolicy:
    """Tests for create_default_policy method."""

    def test_create_default_user_home_policy(self, user_home_creator):
        """Test creating default user home policy."""
        result = user_home_creator.create_default_policy()

        # Should return self for chaining
        assert result is user_home_creator

        # Should have statements in sections
        sections = user_home_creator.get_sections()
        total_statements = sum(len(stmts) for stmts in sections.values())
        assert total_statements > 0

    def test_create_default_user_system_policy(self, user_system_creator):
        """Test creating default user system policy."""
        result = user_system_creator.create_default_policy()

        assert result is user_system_creator

        sections = user_system_creator.get_sections()
        total_statements = sum(len(stmts) for stmts in sections.values())
        assert total_statements > 0

    def test_create_default_group_policy(self, group_policy_creator):
        """Test creating default group policy."""
        result = group_policy_creator.create_default_policy()

        assert result is group_policy_creator

        sections = group_policy_creator.get_sections()
        total_statements = sum(len(stmts) for stmts in sections.values())
        assert total_statements > 0

    def test_create_default_group_read_only_policy(
        self, group_read_only_policy_creator
    ):
        """Test creating default group read-only policy with READ permissions only."""
        result = group_read_only_policy_creator.create_default_policy()

        assert result is group_read_only_policy_creator

        sections = group_read_only_policy_creator.get_sections()
        total_statements = sum(len(stmts) for stmts in sections.values())
        assert total_statements > 0

        # Verify it has read permissions but no write/delete
        policy = group_read_only_policy_creator.build()
        actions = [stmt.action for stmt in policy.policy_document.statement]

        # Should have GET_OBJECT (read access)
        assert PolicyAction.GET_OBJECT in actions
        # Should NOT have PUT_OBJECT or DELETE_OBJECT (write access)
        assert PolicyAction.PUT_OBJECT not in actions
        assert PolicyAction.DELETE_OBJECT not in actions


# =============================================================================
# TEST BUILD
# =============================================================================


class TestBuild:
    """Tests for build method."""

    def test_build_user_home_policy(self, user_home_creator):
        """Test building complete user home policy."""
        user_home_creator.create_default_policy()
        policy = user_home_creator.build()

        assert isinstance(policy, PolicyModel)
        assert policy.policy_name == "user-home-policy-testuser"
        assert isinstance(policy.policy_document, PolicyDocument)
        assert len(policy.policy_document.statement) > 0

    def test_build_user_system_policy(self, user_system_creator):
        """Test building complete user system policy."""
        user_system_creator.create_default_policy()
        policy = user_system_creator.build()

        assert isinstance(policy, PolicyModel)
        assert policy.policy_name == "user-system-policy-testuser"

    def test_build_group_policy(self, group_policy_creator):
        """Test building complete group policy."""
        group_policy_creator.create_default_policy()
        policy = group_policy_creator.build()

        assert isinstance(policy, PolicyModel)
        assert policy.policy_name == "group-policy-testgroup"

    def test_build_group_read_only_policy(self, group_read_only_policy_creator):
        """Test building complete group read-only policy."""
        group_read_only_policy_creator.create_default_policy()
        policy = group_read_only_policy_creator.build()

        assert isinstance(policy, PolicyModel)
        assert policy.policy_name == "group-policy-testgroupro"

    def test_build_empty_policy(self, user_home_creator):
        """Test building policy without creating default (empty sections)."""
        policy = user_home_creator.build()

        assert isinstance(policy, PolicyModel)
        assert policy.policy_name == "user-home-policy-testuser"
        # Empty policy should still be valid
        assert len(policy.policy_document.statement) == 0

    def test_build_returns_valid_json(self, user_home_creator):
        """Test built policy can be converted to JSON."""
        user_home_creator.create_default_policy()
        policy = user_home_creator.build()

        json_str = policy.to_minio_policy_json()
        assert isinstance(json_str, str)
        assert "Version" in json_str
        assert "Statement" in json_str


# =============================================================================
# TEST SECTION ORDERING
# =============================================================================


class TestSectionOrdering:
    """Tests for policy section ordering."""

    def test_combine_sections_ordering(self, user_home_creator):
        """Test sections are combined in correct order."""
        user_home_creator.create_default_policy()
        statements = user_home_creator._combine_sections_with_ordering()

        # Verify statements list is not empty
        assert len(statements) > 0

        # All statements should be PolicyStatement instances
        for stmt in statements:
            assert isinstance(stmt, PolicyStatement)

    def test_section_order_global_first(self, user_home_creator):
        """Test global permissions come first if present."""
        user_home_creator.create_default_policy()
        policy = user_home_creator.build()
        statements = policy.policy_document.statement

        # If there are global permissions, they should be first
        if len(statements) > 0:
            # Check first statements are global if present
            global_actions = {
                PolicyAction.LIST_ALL_MY_BUCKETS,
                PolicyAction.GET_BUCKET_LOCATION,
            }
            first_stmt_action = statements[0].action
            # Either first is global or there are no global statements
            has_global = any(stmt.action in global_actions for stmt in statements)
            if has_global:
                assert first_stmt_action in global_actions


# =============================================================================
# TEST USER SYSTEM PATHS
# =============================================================================


class TestUserSystemPaths:
    """Tests for _get_user_system_paths method."""

    def test_get_user_system_paths_structure(self, user_system_creator):
        """Test user system paths structure."""
        paths = user_system_creator._get_user_system_paths("testuser")

        assert isinstance(paths, dict)
        # Should have entries for each system resource bucket
        for bucket_name, path_list in paths.items():
            assert isinstance(bucket_name, str)
            assert isinstance(path_list, list)
            for path, permission in path_list:
                assert isinstance(path, str)
                assert isinstance(permission, PolicyPermissionLevel)

    def test_get_user_system_paths_user_scoped(self, user_system_creator):
        """Test user-scoped system paths include username."""
        paths = user_system_creator._get_user_system_paths("testuser")

        # Find user-scoped resources
        for resource_name, resource_config in SYSTEM_RESOURCE_CONFIG.items():
            if resource_config["user_scoped"]:
                bucket = resource_config["bucket"]
                base_prefix = resource_config["base_prefix"]
                expected_path = f"{base_prefix}/testuser"

                # Check path is in the results
                bucket_paths = paths.get(bucket, [])
                path_strings = [p[0] for p in bucket_paths]
                assert expected_path in path_strings


# =============================================================================
# TEST CONSTANTS
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_system_resource_config_structure(self):
        """Test SYSTEM_RESOURCE_CONFIG has correct structure."""
        for resource_name, config in SYSTEM_RESOURCE_CONFIG.items():
            assert "bucket" in config
            assert "base_prefix" in config
            assert "user_scoped" in config
            assert "permission_level" in config
            assert isinstance(config["user_scoped"], bool)
            assert isinstance(config["permission_level"], PolicyPermissionLevel)

    def test_policy_action_to_section_mapping(self):
        """Test policy action to section mapping is complete."""
        # Key actions should be mapped
        assert PolicyAction.LIST_ALL_MY_BUCKETS in _POLICY_ACTION_TO_POLICY_SECTION
        assert PolicyAction.GET_BUCKET_LOCATION in _POLICY_ACTION_TO_POLICY_SECTION
        assert PolicyAction.LIST_BUCKET in _POLICY_ACTION_TO_POLICY_SECTION
        assert PolicyAction.GET_OBJECT in _POLICY_ACTION_TO_POLICY_SECTION
        assert PolicyAction.PUT_OBJECT in _POLICY_ACTION_TO_POLICY_SECTION
        assert PolicyAction.DELETE_OBJECT in _POLICY_ACTION_TO_POLICY_SECTION


# =============================================================================
# TEST EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_method_chaining(self, user_home_creator):
        """Test method chaining works correctly."""
        policy = user_home_creator.create_default_policy().build()

        assert isinstance(policy, PolicyModel)

    def test_rebuild_sections_clears_existing(self, user_home_creator):
        """Test _rebuild_sections_from_policy clears existing sections."""
        # Add some statements via create_default_policy
        user_home_creator.create_default_policy()
        initial_policy = user_home_creator.build()

        # Rebuild from same policy - should have same statements
        user_home_creator._rebuild_sections_from_policy(initial_policy)
        rebuilt_policy = user_home_creator.build()

        assert len(initial_policy.policy_document.statement) == len(
            rebuilt_policy.policy_document.statement
        )

    def test_get_current_policy_internal(self, user_home_creator):
        """Test _get_current_policy returns valid PolicyModel."""
        user_home_creator.create_default_policy()
        policy = user_home_creator._get_current_policy()

        assert isinstance(policy, PolicyModel)
        assert policy.policy_name == "user-home-policy-testuser"

    def test_username_with_special_chars(self, mock_minio_config):
        """Test creator handles usernames with allowed special characters."""
        creator = PolicyCreator(
            policy_type=PolicyType.USER_HOME,
            target_name="test.user-name",
            config=mock_minio_config,
        )

        policy = creator.create_default_policy().build()

        assert "test.user-name" in policy.policy_name


# =============================================================================
# TEST INTEGRATION
# =============================================================================


class TestIntegration:
    """Integration tests for PolicyCreator."""

    def test_full_user_home_workflow(self, mock_minio_config):
        """Test complete user home policy creation workflow."""
        creator = PolicyCreator(
            policy_type=PolicyType.USER_HOME,
            target_name="newuser",
            config=mock_minio_config,
        )

        # Create default policy
        creator.create_default_policy()

        # Build final policy
        policy = creator.build()

        # Verify policy structure
        assert policy.policy_name == "user-home-policy-newuser"
        assert policy.policy_document.version == "2012-10-17"
        assert len(policy.policy_document.statement) > 0

        # Verify can serialize to JSON
        json_str = policy.to_minio_policy_json()
        assert "user" in json_str or "User" in json_str

    def test_full_group_workflow(self, mock_minio_config):
        """Test complete group policy creation workflow."""
        creator = PolicyCreator(
            policy_type=PolicyType.GROUP_HOME,
            target_name="researchers",
            config=mock_minio_config,
        )

        creator.create_default_policy()
        policy = creator.build()

        assert policy.policy_name == "group-policy-researchers"
        assert len(policy.policy_document.statement) > 0

    def test_full_group_read_only_workflow(self, mock_minio_config):
        """Test complete group read-only policy creation workflow."""
        creator = PolicyCreator(
            policy_type=PolicyType.GROUP_HOME_RO,
            target_name="researchersro",
            config=mock_minio_config,
        )

        creator.create_default_policy()
        policy = creator.build()

        # Verify policy structure
        assert policy.policy_name == "group-policy-researchers"
        assert policy.policy_document.version == "2012-10-17"
        assert len(policy.policy_document.statement) > 0

        # Verify read-only: has GET but not PUT/DELETE
        actions = [stmt.action for stmt in policy.policy_document.statement]
        assert PolicyAction.GET_OBJECT in actions
        assert PolicyAction.PUT_OBJECT not in actions
        assert PolicyAction.DELETE_OBJECT not in actions

        # Verify can serialize to JSON
        json_str = policy.to_minio_policy_json()
        assert "Statement" in json_str
