"""Comprehensive tests for the minio.managers.resource_manager module."""

import json
import logging
import os
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.minio.core.minio_client import MinIOClient
from src.minio.managers.resource_manager import ResourceManager
from src.minio.models.command import CommandResult
from src.minio.models.minio_config import MinIOConfig
from src.service.exceptions import MinIOManagerError

# =============================================================================
# Test Implementation of ResourceManager
# =============================================================================


class ConcreteResourceManager(ResourceManager[str]):
    """Concrete implementation for testing abstract ResourceManager."""

    def __init__(self, client, config, logger_instance=None):
        super().__init__(client, config, logger_instance)
        self.resource_type = "testresource"

    def _get_resource_type(self) -> str:
        return self.resource_type

    def _validate_resource_name(self, name: str) -> str:
        if not name or not name.strip():
            raise ValueError("Resource name cannot be empty")
        return name.strip()

    def _build_exists_command(self, name: str) -> List[str]:
        return ["mc", "admin", self.resource_type, "info", "minio_api", name]

    def _build_list_command(self) -> List[str]:
        return ["mc", "admin", self.resource_type, "list", "minio_api", "--json"]

    def _build_delete_command(self, name: str) -> List[str]:
        return ["mc", "admin", self.resource_type, "remove", "minio_api", name]

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse JSON output to extract resource names."""

        resources = []
        for line in stdout.strip().split("\n"):
            if line.strip():
                data = json.loads(line)
                resources.append(data.get("name", ""))
        return resources


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Mock MC_PATH environment variable for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_minio_config():
    """Create a mock MinIOConfig."""
    return MinIOConfig(
        endpoint="http://localhost:9000",  # type: ignore
        access_key="test_access",
        secret_key="test_secret",
        secure=False,
        default_bucket="test-bucket",
    )


@pytest.fixture
def mock_minio_client():
    """Create a mock MinIOClient."""
    client = MagicMock(spec=MinIOClient)
    return client


@pytest.fixture
def mock_executor():
    """Create a mock executor."""
    executor = MagicMock()
    executor.setup = AsyncMock()
    executor._execute_command = AsyncMock()
    return executor


@pytest.fixture
def resource_manager(mock_minio_client, mock_minio_config, mock_executor):
    """Create a ConcreteResourceManager with mocked dependencies."""
    manager = ConcreteResourceManager(mock_minio_client, mock_minio_config)
    manager._executor = mock_executor
    return manager


# =============================================================================
# Test Initialization
# =============================================================================


class TestResourceManagerInit:
    """Tests for ResourceManager initialization."""

    def test_init_with_client_and_config(self, mock_minio_client, mock_minio_config):
        """Test initialization with client and config."""
        manager = ConcreteResourceManager(mock_minio_client, mock_minio_config)

        assert manager.client == mock_minio_client
        assert manager.config == mock_minio_config
        assert manager.logger is not None

    def test_init_with_custom_logger(self, mock_minio_client, mock_minio_config):
        """Test initialization with custom logger."""
        custom_logger = logging.getLogger("custom_logger")
        manager = ConcreteResourceManager(
            mock_minio_client, mock_minio_config, custom_logger
        )

        assert manager.logger == custom_logger

    def test_init_creates_executor(self, mock_minio_client, mock_minio_config):
        """Test that initialization creates executor."""
        manager = ConcreteResourceManager(mock_minio_client, mock_minio_config)

        assert manager._executor is not None
        assert manager._command_builder is not None
        assert manager.alias == "minio_api"

    def test_init_uses_custom_alias_from_env(
        self, mock_minio_client, mock_minio_config
    ):
        """Test that custom alias from environment is used."""
        with patch.dict(os.environ, {"MINIO_API_ALIAS": "custom_alias"}):
            manager = ConcreteResourceManager(mock_minio_client, mock_minio_config)
            assert manager.alias == "custom_alias"


# =============================================================================
# Test Operation Context
# =============================================================================


class TestOperationContext:
    """Tests for operation_context context manager."""

    @pytest.mark.asyncio
    async def test_operation_context_success(self, resource_manager, mock_executor):
        """Test operation context with successful operation."""
        async with resource_manager.operation_context("test_operation"):
            pass

        # Executor setup should have been called
        mock_executor.setup.assert_called_once()

    @pytest.mark.asyncio
    async def test_operation_context_logs_start_and_complete(
        self, resource_manager, mock_executor
    ):
        """Test that operation context logs start and completion."""
        with patch.object(resource_manager.logger, "info") as mock_log:
            async with resource_manager.operation_context("test_operation"):
                pass

            # Should log starting and completion
            assert mock_log.call_count >= 2

    @pytest.mark.asyncio
    async def test_operation_context_wraps_exception(
        self, resource_manager, mock_executor
    ):
        """Test that operation context wraps exceptions."""
        with pytest.raises(MinIOManagerError):
            async with resource_manager.operation_context("test_operation"):
                raise RuntimeError("Test error")

    @pytest.mark.asyncio
    async def test_operation_context_preserves_minio_error(
        self, resource_manager, mock_executor
    ):
        """Test that MinIOManagerError is preserved."""
        with pytest.raises(MinIOManagerError) as exc_info:
            async with resource_manager.operation_context("test_operation"):
                raise MinIOManagerError("Original error")

        assert "Original error" in str(exc_info.value)


# =============================================================================
# Test Resource Exists
# =============================================================================


class TestResourceExists:
    """Tests for resource_exists method."""

    @pytest.mark.asyncio
    async def test_resource_exists_returns_true_when_exists(
        self, resource_manager, mock_executor
    ):
        """Test resource_exists returns True when resource exists."""
        mock_executor._execute_command.return_value = CommandResult(
            success=True, stdout="", stderr="", return_code=0, command="test command"
        )

        result = await resource_manager.resource_exists("testresource1")

        assert result is True
        mock_executor._execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_resource_exists_returns_false_when_not_exists(
        self, resource_manager, mock_executor
    ):
        """Test resource_exists returns False when resource doesn't exist."""
        mock_executor._execute_command.return_value = CommandResult(
            success=False, stdout="", stderr="not found", return_code=1, command="test"
        )

        result = await resource_manager.resource_exists("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_resource_exists_validates_name(
        self, resource_manager, mock_executor
    ):
        """Test resource_exists validates resource name."""
        await resource_manager.resource_exists("  valid_name  ")

        # Should have been validated and trimmed
        args = mock_executor._execute_command.call_args[0][0]
        assert "valid_name" in args

    @pytest.mark.asyncio
    async def test_resource_exists_handles_exceptions_gracefully(
        self, resource_manager, mock_executor
    ):
        """Test resource_exists handles exceptions gracefully."""
        mock_executor._execute_command.side_effect = Exception("Command failed")

        result = await resource_manager.resource_exists("testresource")

        assert result is False


# =============================================================================
# Test List Resources
# =============================================================================


class TestListResources:
    """Tests for list_resources method."""

    @pytest.mark.asyncio
    async def test_list_resources_success(self, resource_manager, mock_executor):
        """Test list_resources successfully lists resources."""
        stdout = '{"name": "resource1"}\n{"name": "resource2"}\n{"name": "resource3"}'
        mock_executor._execute_command.return_value = CommandResult(
            success=True, stdout=stdout, stderr="", return_code=0, command="test"
        )

        resources = await resource_manager.list_resources()

        assert len(resources) == 3
        assert "resource1" in resources
        assert "resource2" in resources
        assert "resource3" in resources

    @pytest.mark.asyncio
    async def test_list_resources_with_filter(self, resource_manager, mock_executor):
        """Test list_resources with name filter."""
        stdout = '{"name": "test1"}\n{"name": "prod1"}\n{"name": "test2"}'
        mock_executor._execute_command.return_value = CommandResult(
            success=True, stdout=stdout, stderr="", return_code=0, command="test"
        )

        resources = await resource_manager.list_resources(name_filter="test")

        assert len(resources) == 2
        assert "test1" in resources
        assert "test2" in resources
        assert "prod1" not in resources

    @pytest.mark.asyncio
    async def test_list_resources_returns_sorted(self, resource_manager, mock_executor):
        """Test list_resources returns sorted list."""
        stdout = '{"name": "zebra"}\n{"name": "apple"}\n{"name": "banana"}'
        mock_executor._execute_command.return_value = CommandResult(
            success=True, stdout=stdout, stderr="", return_code=0, command="test"
        )

        resources = await resource_manager.list_resources()

        assert resources == ["apple", "banana", "zebra"]

    @pytest.mark.asyncio
    async def test_list_resources_empty_result(self, resource_manager, mock_executor):
        """Test list_resources with no resources."""
        mock_executor._execute_command.return_value = CommandResult(
            success=True, stdout="", stderr="", return_code=0, command="test"
        )

        resources = await resource_manager.list_resources()

        assert resources == []

    @pytest.mark.asyncio
    async def test_list_resources_command_failure(
        self, resource_manager, mock_executor
    ):
        """Test list_resources when command fails."""
        mock_executor._execute_command.return_value = CommandResult(
            success=False, stdout="", stderr="error", return_code=1, command="test"
        )

        resources = await resource_manager.list_resources()

        assert resources == []

    @pytest.mark.asyncio
    async def test_list_resources_exception_handling(
        self, resource_manager, mock_executor
    ):
        """Test list_resources handles exceptions."""
        mock_executor._execute_command.side_effect = Exception("Command error")

        resources = await resource_manager.list_resources()

        assert resources == []


# =============================================================================
# Test Delete Resource
# =============================================================================


class TestDeleteResource:
    """Tests for delete_resource method."""

    @pytest.mark.asyncio
    async def test_delete_resource_success(self, resource_manager, mock_executor):
        """Test successful resource deletion."""
        # Mock exists check
        mock_executor._execute_command.side_effect = [
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # exists
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # delete
        ]

        result = await resource_manager.delete_resource("testresource")

        assert result is True
        assert mock_executor._execute_command.call_count == 2

    @pytest.mark.asyncio
    async def test_delete_resource_not_exists(self, resource_manager, mock_executor):
        """Test delete_resource when resource doesn't exist."""
        mock_executor._execute_command.return_value = CommandResult(
            success=False, stdout="", stderr="not found", return_code=1, command="test"
        )

        result = await resource_manager.delete_resource("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_resource_validates_name(
        self, resource_manager, mock_executor
    ):
        """Test delete_resource validates name."""
        mock_executor._execute_command.return_value = CommandResult(
            success=True, stdout="", stderr="", return_code=0, command="test"
        )

        await resource_manager.delete_resource("  resource_name  ")

        # Name should have been validated/trimmed
        args_list = [
            call[0][0] for call in mock_executor._execute_command.call_args_list
        ]
        assert any("resource_name" in str(args) for args in args_list)

    @pytest.mark.asyncio
    async def test_delete_resource_calls_pre_delete_cleanup(
        self, resource_manager, mock_executor
    ):
        """Test that delete_resource calls pre-delete cleanup."""
        mock_executor._execute_command.side_effect = [
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # exists
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # delete
        ]

        with patch.object(
            resource_manager, "_pre_delete_cleanup", new=AsyncMock()
        ) as mock_cleanup:
            await resource_manager.delete_resource("testresource")
            mock_cleanup.assert_called_once_with("testresource", False)

    @pytest.mark.asyncio
    async def test_delete_resource_calls_post_delete_cleanup(
        self, resource_manager, mock_executor
    ):
        """Test that delete_resource calls post-delete cleanup."""
        mock_executor._execute_command.side_effect = [
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # exists
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # delete
        ]

        with patch.object(
            resource_manager, "_post_delete_cleanup", new=AsyncMock()
        ) as mock_cleanup:
            await resource_manager.delete_resource("testresource")
            mock_cleanup.assert_called_once_with("testresource")

    @pytest.mark.asyncio
    async def test_delete_resource_force_flag(self, resource_manager, mock_executor):
        """Test delete_resource with force flag."""
        mock_executor._execute_command.side_effect = [
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # exists
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # delete
        ]

        with patch.object(
            resource_manager, "_pre_delete_cleanup", new=AsyncMock()
        ) as mock_cleanup:
            await resource_manager.delete_resource("testresource", force=True)
            mock_cleanup.assert_called_once_with("testresource", True)

    @pytest.mark.asyncio
    async def test_delete_resource_command_fails(self, resource_manager, mock_executor):
        """Test delete_resource when delete command fails."""
        mock_executor._execute_command.side_effect = [
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),  # exists
            CommandResult(
                success=False,
                stdout="",
                stderr="delete failed",
                return_code=1,
                command="test",
            ),  # delete
        ]

        result = await resource_manager.delete_resource("testresource")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_resource_exception_handling(
        self, resource_manager, mock_executor
    ):
        """Test delete_resource handles exceptions."""
        mock_executor._execute_command.side_effect = Exception("Command error")

        result = await resource_manager.delete_resource("testresource")

        assert result is False


# =============================================================================
# Test Cleanup Hooks
# =============================================================================


class TestCleanupHooks:
    """Tests for cleanup hook methods."""

    @pytest.mark.asyncio
    async def test_pre_delete_cleanup_default_implementation(self, resource_manager):
        """Test that default _pre_delete_cleanup does nothing."""
        # Should not raise any errors
        await resource_manager._pre_delete_cleanup("testresource")
        await resource_manager._pre_delete_cleanup("testresource", force=True)

    @pytest.mark.asyncio
    async def test_post_delete_cleanup_default_implementation(self, resource_manager):
        """Test that default _post_delete_cleanup does nothing."""
        # Should not raise any errors
        await resource_manager._post_delete_cleanup("testresource")


# =============================================================================
# Test Abstract Methods
# =============================================================================


class TestAbstractMethods:
    """Tests for abstract method implementations."""

    def test_get_resource_type(self, resource_manager):
        """Test _get_resource_type implementation."""
        assert resource_manager._get_resource_type() == "testresource"

    def test_validate_resource_name_valid(self, resource_manager):
        """Test _validate_resource_name with valid name."""
        assert resource_manager._validate_resource_name("test") == "test"
        assert resource_manager._validate_resource_name("  test  ") == "test"

    def test_validate_resource_name_invalid(self, resource_manager):
        """Test _validate_resource_name with invalid name."""
        with pytest.raises(ValueError):
            resource_manager._validate_resource_name("")
        with pytest.raises(ValueError):
            resource_manager._validate_resource_name("   ")

    def test_build_exists_command(self, resource_manager):
        """Test _build_exists_command implementation."""
        cmd = resource_manager._build_exists_command("testname")
        assert "testname" in cmd
        assert "info" in cmd

    def test_build_list_command(self, resource_manager):
        """Test _build_list_command implementation."""
        cmd = resource_manager._build_list_command()
        assert "list" in cmd
        assert "--json" in cmd

    def test_build_delete_command(self, resource_manager):
        """Test _build_delete_command implementation."""
        cmd = resource_manager._build_delete_command("testname")
        assert "testname" in cmd
        assert "remove" in cmd

    def test_parse_list_output(self, resource_manager):
        """Test _parse_list_output implementation."""
        stdout = '{"name": "res1"}\n{"name": "res2"}'
        names = resource_manager._parse_list_output(stdout)
        assert names == ["res1", "res2"]


# =============================================================================
# Test Executor Setup
# =============================================================================


class TestExecutorSetup:
    """Tests for ensure_executor_setup method."""

    @pytest.mark.asyncio
    async def test_ensure_executor_setup_calls_setup(
        self, resource_manager, mock_executor
    ):
        """Test ensure_executor_setup calls executor setup."""
        await resource_manager.ensure_executor_setup()

        mock_executor.setup.assert_called_once()


# =============================================================================
# Test Integration
# =============================================================================


class TestIntegration:
    """Integration tests for ResourceManager."""

    @pytest.mark.asyncio
    async def test_full_resource_lifecycle(self, resource_manager, mock_executor):
        """Test complete resource lifecycle: list, check exists, delete."""
        # Setup mock responses
        mock_executor._execute_command.side_effect = [
            # list resources
            CommandResult(
                success=True,
                stdout='{"name": "res1"}\n{"name": "res2"}',
                stderr="",
                return_code=0,
                command="test",
            ),
            # check exists for res1
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),
            # delete res1 - exists check inside delete
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),
            # delete res1 - actual delete
            CommandResult(
                success=True, stdout="", stderr="", return_code=0, command="test"
            ),
        ]

        # List resources
        resources = await resource_manager.list_resources()
        assert len(resources) == 2

        # Check one exists
        exists = await resource_manager.resource_exists("res1")
        assert exists is True

        # Delete it
        deleted = await resource_manager.delete_resource("res1")
        assert deleted is True
