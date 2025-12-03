"""Comprehensive tests for the minio.core.base_executor module."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.minio.core.base_executor import BaseMinIOExecutor
from src.minio.models.command import CommandResult
from src.service.exceptions import MinIOManagerError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def mock_env_vars():
    """Mock required environment variables."""
    with patch.dict(
        os.environ,
        {
            "MC_PATH": "/usr/local/bin/mc",
            "MINIO_ROOT_USER": "admin",
            "MINIO_ROOT_PASSWORD": "password123",
        },
    ):
        yield


@pytest.fixture
def mock_minio_config():
    """Create a mock MinIOConfig."""
    config = MagicMock()
    config.endpoint = "http://minio:9000"
    config.minio_url = "http://minio:9000"
    config.minio_access_key = "admin"
    config.minio_secret_key = "password123"
    return config


@pytest.fixture
def executor(mock_minio_config):
    """Create a BaseMinIOExecutor instance."""
    return BaseMinIOExecutor(mock_minio_config)


@pytest.fixture
def executor_with_custom_alias(mock_minio_config):
    """Create a BaseMinIOExecutor with custom alias."""
    return BaseMinIOExecutor(mock_minio_config, alias="custom_alias")


# =============================================================================
# TEST INITIALIZATION
# =============================================================================


class TestBaseMinIOExecutorInit:
    """Tests for BaseMinIOExecutor initialization."""

    def test_init_with_defaults(self, mock_minio_config):
        """Test initialization with default parameters."""
        executor = BaseMinIOExecutor(mock_minio_config)

        assert executor.config == mock_minio_config
        assert executor.alias == "minio_api"
        assert executor._mc_path == "/usr/local/bin/mc"
        assert executor._setup_complete is False

    def test_init_with_custom_alias(self, mock_minio_config):
        """Test initialization with custom alias."""
        executor = BaseMinIOExecutor(mock_minio_config, alias="custom")

        assert executor.alias == "custom"

    def test_init_without_mc_path_raises_error(self, mock_minio_config):
        """Test initialization fails without MC_PATH."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("MC_PATH", None)

            with pytest.raises(KeyError):
                BaseMinIOExecutor(mock_minio_config)

    def test_init_with_empty_mc_path_raises_error(self, mock_minio_config):
        """Test initialization fails with empty MC_PATH."""
        with patch.dict(os.environ, {"MC_PATH": ""}):
            with pytest.raises(ValueError):
                BaseMinIOExecutor(mock_minio_config)

    def test_command_builder_initialized(self, executor):
        """Test command builder is initialized with alias."""
        assert executor._command_builder is not None
        assert executor._command_builder.alias == executor.alias


# =============================================================================
# TEST SETUP
# =============================================================================


class TestSetup:
    """Tests for setup method."""

    @pytest.mark.asyncio
    async def test_setup_success(self, executor):
        """Test successful setup."""
        with patch.object(executor, "_execute_command") as mock_execute:
            mock_execute.return_value = CommandResult(
                success=True,
                stdout="Alias set successfully",
                stderr="",
                return_code=0,
                command="mc alias set",
            )

            await executor.setup()

            assert executor._setup_complete is True
            mock_execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_idempotent(self, executor):
        """Test setup is idempotent - only runs once."""
        with patch.object(executor, "_execute_command") as mock_execute:
            mock_execute.return_value = CommandResult(
                success=True,
                stdout="",
                stderr="",
                return_code=0,
                command="mc alias set",
            )

            await executor.setup()
            await executor.setup()  # Second call should be no-op

            # Should only be called once
            mock_execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_command_failure(self, executor):
        """Test setup handles command failure."""
        with patch.object(executor, "_execute_command") as mock_execute:
            mock_execute.return_value = CommandResult(
                success=False,
                stdout="",
                stderr="Access denied",
                return_code=1,
                command="mc alias set",
            )

            with pytest.raises(MinIOManagerError) as exc_info:
                await executor.setup()

            assert "Failed to configure MinIO" in str(exc_info.value)
            assert executor._setup_complete is False

    @pytest.mark.asyncio
    async def test_setup_without_minio_root_user(self, mock_minio_config):
        """Test setup fails without MINIO_ROOT_USER."""
        with patch.dict(
            os.environ, {"MC_PATH": "/usr/local/bin/mc", "MINIO_ROOT_PASSWORD": "pass"}
        ):
            os.environ.pop("MINIO_ROOT_USER", None)

            executor = BaseMinIOExecutor(mock_minio_config)

            with pytest.raises((MinIOManagerError, ValueError)):
                await executor.setup()

    @pytest.mark.asyncio
    async def test_setup_without_minio_root_password(self, mock_minio_config):
        """Test setup fails without MINIO_ROOT_PASSWORD."""
        with patch.dict(
            os.environ, {"MC_PATH": "/usr/local/bin/mc", "MINIO_ROOT_USER": "admin"}
        ):
            os.environ.pop("MINIO_ROOT_PASSWORD", None)

            executor = BaseMinIOExecutor(mock_minio_config)

            with pytest.raises((MinIOManagerError, ValueError)):
                await executor.setup()


# =============================================================================
# TEST EXECUTE COMMAND
# =============================================================================


class TestExecuteCommand:
    """Tests for _execute_command method."""

    @pytest.mark.asyncio
    async def test_execute_command_success(self, executor):
        """Test successful command execution."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"success output", b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(["admin", "user", "list"])

            assert result.success is True
            assert result.stdout == "success output"
            assert result.stderr == ""
            assert result.return_code == 0

    @pytest.mark.asyncio
    async def test_execute_command_failure(self, executor):
        """Test command execution failure."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"", b"error message")
        mock_process.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(
                ["admin", "user", "info", "nonexistent"]
            )

            assert result.success is False
            assert result.stderr == "error message"
            assert result.return_code == 1

    @pytest.mark.asyncio
    async def test_execute_command_timeout(self, executor):
        """Test command execution timeout."""
        mock_process = AsyncMock()
        mock_process.communicate.side_effect = asyncio.TimeoutError()
        mock_process.kill = AsyncMock()
        mock_process.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(
                ["admin", "user", "list"], timeout=1
            )

            assert result.success is False
            assert "timed out" in result.stderr.lower()
            assert result.return_code == -1
            mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_command_with_input_data(self, executor):
        """Test command execution with stdin input."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"output", b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            await executor._execute_command(
                ["admin", "policy", "create"], input_data='{"Version": "2012-10-17"}'
            )

            # Verify stdin was passed
            mock_process.communicate.assert_called_once()
            call_args = mock_process.communicate.call_args
            assert call_args[1]["input"] == b'{"Version": "2012-10-17"}'

    @pytest.mark.asyncio
    async def test_execute_command_exception(self, executor):
        """Test command execution raises MinIOManagerError on exception."""
        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Unexpected error")
        ):
            with pytest.raises(MinIOManagerError) as exc_info:
                await executor._execute_command(["admin", "user", "list"])

            assert "Unexpected error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_command_custom_timeout(self, executor):
        """Test command execution with custom timeout."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"output", b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait_for:
                mock_wait_for.return_value = (b"output", b"")

                await executor._execute_command(["admin", "user", "list"], timeout=60)

                # Verify custom timeout was used
                mock_wait_for.assert_called_once()
                call_args = mock_wait_for.call_args
                assert call_args[1]["timeout"] == 60

    @pytest.mark.asyncio
    async def test_execute_command_builds_correct_command(self, executor):
        """Test command is built correctly with MC path."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"output", b"")
        mock_process.returncode = 0

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await executor._execute_command(["admin", "user", "list", "minio_api"])

            # Verify MC path is prepended
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "/usr/local/bin/mc"
            assert "admin" in call_args
            assert "user" in call_args
            assert "list" in call_args

    @pytest.mark.asyncio
    async def test_execute_command_result_includes_command_string(self, executor):
        """Test result includes the executed command string."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"", b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(["admin", "user", "list"])

            assert "admin" in result.command
            assert "user" in result.command
            assert "list" in result.command

    @pytest.mark.asyncio
    async def test_execute_command_strips_output(self, executor):
        """Test command output is stripped of whitespace."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (
            b"  output with spaces  \n",
            b"  error  \n",
        )
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(["admin", "user", "list"])

            assert result.stdout == "output with spaces"
            assert result.stderr == "error"

    @pytest.mark.asyncio
    async def test_execute_command_handles_unicode(self, executor):
        """Test command handles unicode output."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = ("日本語output".encode("utf-8"), b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(["admin", "user", "list"])

            assert "日本語output" in result.stdout


# =============================================================================
# TEST COMMAND RESULT
# =============================================================================


class TestCommandResult:
    """Tests for CommandResult model."""

    def test_command_result_success(self):
        """Test successful CommandResult."""
        result = CommandResult(
            success=True,
            stdout="output",
            stderr="",
            return_code=0,
            command="mc admin user list",
        )

        assert result.success is True
        assert result.failed is False
        assert result.has_output is True
        assert result.has_error is False

    def test_command_result_failure(self):
        """Test failed CommandResult."""
        result = CommandResult(
            success=False,
            stdout="",
            stderr="error message",
            return_code=1,
            command="mc admin user info nonexistent",
        )

        assert result.success is False
        assert result.failed is True
        assert result.has_output is False
        assert result.has_error is True

    def test_command_result_empty_output(self):
        """Test CommandResult with empty output."""
        result = CommandResult(
            success=True,
            stdout="",
            stderr="",
            return_code=0,
            command="mc admin user list",
        )

        assert result.has_output is False
        assert result.has_error is False

    def test_command_result_whitespace_output(self):
        """Test CommandResult with whitespace-only output."""
        result = CommandResult(
            success=True,
            stdout="   ",
            stderr="   ",
            return_code=0,
            command="mc admin user list",
        )

        # Whitespace-only should not count as output
        assert result.has_output is False
        assert result.has_error is False


# =============================================================================
# TEST EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_process_already_terminated_on_kill(self, executor):
        """Test handling when process is already terminated during kill."""
        mock_process = AsyncMock()
        mock_process.communicate.side_effect = asyncio.TimeoutError()
        mock_process.kill.side_effect = ProcessLookupError()
        mock_process.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            # Should not raise even if process already terminated
            result = await executor._execute_command(
                ["admin", "user", "list"], timeout=1
            )

            assert result.success is False

    @pytest.mark.asyncio
    async def test_return_code_none_handled(self, executor):
        """Test handling when return_code is None."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"output", b"")
        mock_process.returncode = None

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(["admin", "user", "list"])

            # None should be treated as 0 (success)
            assert result.return_code == 0
            assert result.success is True

    @pytest.mark.asyncio
    async def test_invalid_utf8_output_handled(self, executor):
        """Test handling of invalid UTF-8 in output."""
        mock_process = AsyncMock()
        # Invalid UTF-8 bytes
        mock_process.communicate.return_value = (b"\xff\xfe invalid", b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await executor._execute_command(["admin", "user", "list"])

            # Should handle gracefully with errors='replace'
            assert result.success is True

    def test_executor_alias_used_in_commands(self, executor_with_custom_alias):
        """Test custom alias is used in command builder."""
        assert executor_with_custom_alias._command_builder.alias == "custom_alias"


# =============================================================================
# TEST INTEGRATION SCENARIOS
# =============================================================================


class TestIntegrationScenarios:
    """Tests for integration-like scenarios."""

    @pytest.mark.asyncio
    async def test_setup_then_execute(self, executor):
        """Test full workflow: setup then execute commands."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"success", b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            # Setup
            await executor.setup()
            assert executor._setup_complete is True

            # Execute command after setup
            result = await executor._execute_command(["admin", "user", "list"])
            assert result.success is True

    @pytest.mark.asyncio
    async def test_multiple_commands_after_setup(self, executor):
        """Test executing multiple commands after setup."""
        call_count = 0

        async def mock_communicate(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return (f"output{call_count}".encode(), b"")

        mock_process = AsyncMock()
        mock_process.communicate = mock_communicate
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            await executor.setup()

            result1 = await executor._execute_command(["admin", "user", "list"])
            result2 = await executor._execute_command(["admin", "group", "list"])

            # Each command should have different output
            assert "output" in result1.stdout
            assert "output" in result2.stdout
