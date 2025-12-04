"""Comprehensive tests for the minio.core.command_builder module."""

import pytest

from src.minio.core.command_builder import MinIOCommandBuilder
from src.minio.models.command import GroupAction, PolicyAction, UserAction
from src.service.exceptions import GroupOperationError, UserOperationError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def command_builder():
    """Create a MinIOCommandBuilder instance."""
    return MinIOCommandBuilder(alias="minio_api")


@pytest.fixture
def custom_alias_builder():
    """Create a MinIOCommandBuilder with custom alias."""
    return MinIOCommandBuilder(alias="custom_alias")


# =============================================================================
# TEST INITIALIZATION
# =============================================================================


class TestMinIOCommandBuilderInit:
    """Tests for MinIOCommandBuilder initialization."""

    def test_init_with_alias(self):
        """Test initialization with alias."""
        builder = MinIOCommandBuilder(alias="test_alias")
        assert builder.alias == "test_alias"

    def test_init_with_default_alias_pattern(self):
        """Test initialization with default alias pattern."""
        builder = MinIOCommandBuilder(alias="minio_api")
        assert builder.alias == "minio_api"


# =============================================================================
# TEST ALIAS COMMANDS
# =============================================================================


class TestAliasCommands:
    """Tests for alias command building."""

    def test_build_alias_set_command(self, command_builder):
        """Test building alias set command."""
        cmd = command_builder.build_alias_set_command(
            endpoint="http://minio:9000", access_key="admin", secret_key="password"
        )

        assert cmd == [
            "alias",
            "set",
            "minio_api",
            "http://minio:9000",
            "admin",
            "password",
            "--api",
            "S3v4",
        ]

    def test_build_alias_set_command_with_https(self, command_builder):
        """Test building alias set command with HTTPS endpoint."""
        cmd = command_builder.build_alias_set_command(
            endpoint="https://minio.example.com:9000",
            access_key="admin",
            secret_key="password",
        )

        assert "https://minio.example.com:9000" in cmd


# =============================================================================
# TEST USER COMMANDS
# =============================================================================


class TestUserCommands:
    """Tests for user command building."""

    def test_build_user_add_command(self, command_builder):
        """Test building user add command."""
        cmd = command_builder.build_user_command(
            action=UserAction.ADD, username="testuser", password="testpassword"
        )

        assert cmd == ["admin", "user", "add", "minio_api", "testuser", "testpassword"]

    def test_build_user_add_command_without_password(self, command_builder):
        """Test building user add command without password."""
        cmd = command_builder.build_user_command(
            action=UserAction.ADD, username="testuser"
        )

        assert cmd == ["admin", "user", "add", "minio_api", "testuser"]

    def test_build_user_remove_command(self, command_builder):
        """Test building user remove command."""
        cmd = command_builder.build_user_command(
            action=UserAction.REMOVE, username="testuser"
        )

        assert cmd == ["admin", "user", "remove", "minio_api", "testuser"]

    def test_build_user_info_command(self, command_builder):
        """Test building user info command."""
        cmd = command_builder.build_user_command(
            action=UserAction.INFO, username="testuser"
        )

        assert cmd == ["admin", "user", "info", "minio_api", "testuser"]

    def test_build_user_command_validates_username(self, command_builder):
        """Test user command validates username."""
        # Invalid username should raise error
        with pytest.raises(UserOperationError):
            command_builder.build_user_command(
                action=UserAction.INFO,
                username="admin",  # Reserved username
            )

    def test_build_user_list_command(self, command_builder):
        """Test building user list command."""
        cmd = command_builder.build_user_list_command()

        assert cmd == ["admin", "user", "list", "minio_api", "--json"]

    def test_build_user_list_command_without_json(self, command_builder):
        """Test building user list command without JSON format."""
        cmd = command_builder.build_user_list_command(json_format=False)

        assert cmd == ["admin", "user", "list", "minio_api"]
        assert "--json" not in cmd


# =============================================================================
# TEST POLICY COMMANDS
# =============================================================================


class TestPolicyCommands:
    """Tests for policy command building."""

    def test_build_policy_create_command(self, command_builder):
        """Test building policy create command."""
        cmd = command_builder.build_policy_command(
            action=PolicyAction.CREATE,
            policy_name="test-policy",
            file_path="/tmp/policy.json",
        )

        assert cmd == [
            "admin",
            "policy",
            "create",
            "minio_api",
            "test-policy",
            "/tmp/policy.json",
        ]

    def test_build_policy_create_without_file_raises_error(self, command_builder):
        """Test policy create without file path raises error."""
        with pytest.raises(ValueError) as exc_info:
            command_builder.build_policy_command(
                action=PolicyAction.CREATE, policy_name="test-policy"
            )

        assert "File path is required" in str(exc_info.value)

    def test_build_policy_delete_command(self, command_builder):
        """Test building policy delete command."""
        cmd = command_builder.build_policy_command(
            action=PolicyAction.DELETE, policy_name="test-policy"
        )

        assert cmd == ["admin", "policy", "remove", "minio_api", "test-policy"]

    def test_build_policy_info_command(self, command_builder):
        """Test building policy info command."""
        cmd = command_builder.build_policy_command(
            action=PolicyAction.INFO, policy_name="test-policy"
        )

        assert cmd == ["admin", "policy", "info", "minio_api", "test-policy"]

    def test_build_policy_list_command(self, command_builder):
        """Test building policy list command."""
        cmd = command_builder.build_policy_command(
            action=PolicyAction.LIST, json_format=True
        )

        assert cmd == ["admin", "policy", "list", "minio_api", "--json"]

    def test_build_policy_list_without_json(self, command_builder):
        """Test building policy list command without JSON."""
        cmd = command_builder.build_policy_command(
            action=PolicyAction.LIST, json_format=False
        )

        assert cmd == ["admin", "policy", "list", "minio_api"]
        assert "--json" not in cmd

    def test_build_policy_command_without_name_raises_error(self, command_builder):
        """Test policy command without name raises error (except LIST)."""
        with pytest.raises(ValueError) as exc_info:
            command_builder.build_policy_command(action=PolicyAction.INFO)

        assert "Policy name is required" in str(exc_info.value)

    def test_build_policy_attach_command(self, command_builder):
        """Test building policy attach command."""
        cmd = command_builder.build_policy_attach_command(
            policy_name="test-policy", target_type="user", target_name="testuser"
        )

        assert cmd == [
            "admin",
            "policy",
            "attach",
            "minio_api",
            "test-policy",
            "--user",
            "testuser",
        ]

    def test_build_policy_attach_to_group(self, command_builder):
        """Test building policy attach command for group."""
        cmd = command_builder.build_policy_attach_command(
            policy_name="test-policy", target_type="group", target_name="testgroup"
        )

        assert cmd == [
            "admin",
            "policy",
            "attach",
            "minio_api",
            "test-policy",
            "--group",
            "testgroup",
        ]

    def test_build_policy_detach_command(self, command_builder):
        """Test building policy detach command."""
        cmd = command_builder.build_policy_detach_command(
            policy_name="test-policy", target_type="user", target_name="testuser"
        )

        assert cmd == [
            "admin",
            "policy",
            "detach",
            "minio_api",
            "test-policy",
            "--user",
            "testuser",
        ]

    def test_build_policy_detach_from_group(self, command_builder):
        """Test building policy detach command for group."""
        cmd = command_builder.build_policy_detach_command(
            policy_name="test-policy", target_type="group", target_name="testgroup"
        )

        assert cmd == [
            "admin",
            "policy",
            "detach",
            "minio_api",
            "test-policy",
            "--group",
            "testgroup",
        ]

    def test_build_policy_entities_command(self, command_builder):
        """Test building policy entities command."""
        cmd = command_builder.build_policy_entities_command(policy_name="test-policy")

        assert cmd == [
            "admin",
            "policy",
            "entities",
            "minio_api",
            "--policy",
            "test-policy",
            "--json",
        ]


# =============================================================================
# TEST GROUP COMMANDS
# =============================================================================


class TestGroupCommands:
    """Tests for group command building."""

    def test_build_group_add_command(self, command_builder):
        """Test building group add command."""
        cmd = command_builder.build_group_command(
            action=GroupAction.ADD, group_name="testgroup", members=["user1", "user2"]
        )

        assert cmd == [
            "admin",
            "group",
            "add",
            "minio_api",
            "testgroup",
            "user1",
            "user2",
        ]

    def test_build_group_add_without_members(self, command_builder):
        """Test building group add command without members."""
        cmd = command_builder.build_group_command(
            action=GroupAction.ADD, group_name="testgroup"
        )

        assert cmd == ["admin", "group", "add", "minio_api", "testgroup"]

    def test_build_group_rm_command(self, command_builder):
        """Test building group remove command."""
        cmd = command_builder.build_group_command(
            action=GroupAction.RM, group_name="testgroup", members=["user1"]
        )

        assert cmd == ["admin", "group", "rm", "minio_api", "testgroup", "user1"]

    def test_build_group_info_command(self, command_builder):
        """Test building group info command."""
        cmd = command_builder.build_group_command(
            action=GroupAction.INFO, group_name="testgroup"
        )

        assert cmd == ["admin", "group", "info", "minio_api", "testgroup"]

    def test_build_group_info_with_json(self, command_builder):
        """Test building group info command with JSON format."""
        cmd = command_builder.build_group_command(
            action=GroupAction.INFO, group_name="testgroup", json_format=True
        )

        assert cmd == ["admin", "group", "info", "minio_api", "testgroup", "--json"]

    def test_build_group_command_validates_name(self, command_builder):
        """Test group command validates group name."""
        # Invalid group name should raise error
        with pytest.raises(GroupOperationError):
            command_builder.build_group_command(
                action=GroupAction.INFO,
                group_name="admin",  # Reserved group name
            )

    def test_build_group_command_validates_uppercase(self, command_builder):
        """Test group command rejects uppercase names."""
        with pytest.raises(GroupOperationError):
            command_builder.build_group_command(
                action=GroupAction.INFO, group_name="TestGroup"
            )

    def test_build_group_list_command(self, command_builder):
        """Test building group list command."""
        cmd = command_builder.build_group_list_command()

        assert cmd == ["admin", "group", "ls", "minio_api", "--json"]


# =============================================================================
# TEST WITH CUSTOM ALIAS
# =============================================================================


class TestCustomAlias:
    """Tests for commands with custom alias."""

    def test_alias_used_in_all_commands(self, custom_alias_builder):
        """Test custom alias is used in all commands."""
        # User command
        user_cmd = custom_alias_builder.build_user_command(
            action=UserAction.INFO, username="testuser"
        )
        assert "custom_alias" in user_cmd

        # Policy command
        policy_cmd = custom_alias_builder.build_policy_command(
            action=PolicyAction.LIST, json_format=True
        )
        assert "custom_alias" in policy_cmd

        # Group command
        group_cmd = custom_alias_builder.build_group_command(
            action=GroupAction.INFO, group_name="testgroup"
        )
        assert "custom_alias" in group_cmd


# =============================================================================
# TEST EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_members_list(self, command_builder):
        """Test group command with empty members list."""
        cmd = command_builder.build_group_command(
            action=GroupAction.ADD, group_name="testgroup", members=[]
        )

        # Empty list should not add any members
        assert cmd == ["admin", "group", "add", "minio_api", "testgroup"]

    def test_policy_name_with_hyphens(self, command_builder):
        """Test policy command with hyphenated policy name."""
        cmd = command_builder.build_policy_command(
            action=PolicyAction.INFO, policy_name="user-home-policy-testuser"
        )

        assert "user-home-policy-testuser" in cmd

    def test_policy_name_with_underscores(self, command_builder):
        """Test policy command with underscored policy name."""
        cmd = command_builder.build_policy_command(
            action=PolicyAction.INFO, policy_name="user_home_policy_testuser"
        )

        assert "user_home_policy_testuser" in cmd

    def test_username_with_dots(self, command_builder):
        """Test user command with dots in username."""
        cmd = command_builder.build_user_command(
            action=UserAction.INFO, username="user.name"
        )

        assert "user.name" in cmd

    def test_username_with_hyphens(self, command_builder):
        """Test user command with hyphens in username."""
        cmd = command_builder.build_user_command(
            action=UserAction.INFO, username="user-name"
        )

        assert "user-name" in cmd

    def test_group_name_all_lowercase(self, command_builder):
        """Test group name must be all lowercase."""
        # Valid lowercase name
        cmd = command_builder.build_group_command(
            action=GroupAction.INFO, group_name="testgroup123"
        )

        assert "testgroup123" in cmd

    def test_json_flag_only_for_appropriate_actions(self, command_builder):
        """Test JSON flag is only added for appropriate actions."""
        # JSON flag for INFO action in groups
        info_cmd = command_builder.build_group_command(
            action=GroupAction.INFO, group_name="testgroup", json_format=True
        )
        assert "--json" in info_cmd

        # JSON flag should NOT be added for ADD action even if requested
        add_cmd = command_builder.build_group_command(
            action=GroupAction.ADD,
            group_name="testgroup",
            json_format=True,  # This should be ignored
        )
        assert "--json" not in add_cmd
