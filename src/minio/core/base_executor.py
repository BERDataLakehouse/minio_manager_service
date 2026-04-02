"""Base command executor for MinIO operations."""

import asyncio
import logging
import os
from typing import Optional

from ...service.arg_checkers import not_falsy
from ...service.exceptions import S3ManagerError
from ..models.command import CommandResult
from src.s3.models.s3_config import S3Config
from .command_builder import MinIOCommandBuilder

logger = logging.getLogger(__name__)


class BaseMinIOExecutor:
    """Base executor for MinIO MC CLI commands."""

    def __init__(self, config: S3Config, alias: str = "minio_api") -> None:
        """Initialize the executor.

        Args:
            config: MinIO configuration
            alias: MinIO alias name
        """
        self.config = config
        self.alias = alias
        self._mc_path = not_falsy(os.environ["MC_PATH"], "MC_PATH")
        self._command_builder = MinIOCommandBuilder(alias)
        self._setup_complete = False

    async def setup(self) -> None:
        """Initialize the command executor with MC alias setup."""
        if self._setup_complete:
            return

        try:
            # Small delay to ensure MinIO is ready
            await asyncio.sleep(1)

            # Get admin credentials from environment
            admin_user = not_falsy(os.getenv("MINIO_ROOT_USER"), "MINIO_ROOT_USER")
            admin_password = not_falsy(
                os.getenv("MINIO_ROOT_PASSWORD"), "MINIO_ROOT_PASSWORD"
            )

            # Set up MC alias
            cmd_args = self._command_builder.build_alias_set_command(
                str(self.config.endpoint), admin_user, admin_password
            )
            result = await self._execute_command(cmd_args)

            if not result.success:
                raise S3ManagerError(
                    f"Failed to configure MinIO admin access: {result.stderr}"
                )

            logger.info(f"Successfully configured MC alias: {self.alias}")
            self._setup_complete = True

        except Exception as e:
            logger.error(f"Error setting up MC command executor: {e}")
            raise S3ManagerError(f"Failed to initialize MinIO admin client: {e}")

    async def _execute_command(
        self,
        cmd_args: list[str],
        timeout: int = 30,
        input_data: Optional[str] = None,
    ) -> CommandResult:
        """Execute MC command asynchronously.

        Args:
            cmd_args: List of command arguments to pass to MC
            timeout: Command timeout in seconds
            input_data: Optional stdin data for the command

        Returns:
            CommandResult with execution details

        Raises:
            S3ManagerError: If command execution fails unexpectedly
        """
        cmd = [self._mc_path] + cmd_args
        command_str = " ".join(cmd)

        logger.info(f"Executing MC command: {command_str}")

        try:
            # Create subprocess asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None,
            )

            # Execute with timeout
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(
                        input=input_data.encode() if input_data else None
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except ProcessLookupError:
                    pass  # Process already terminated

                logger.error(f"MC command timed out after {timeout}s: {command_str}")
                return CommandResult(
                    success=False,
                    stdout="",
                    stderr=f"Command timed out after {timeout} seconds",
                    return_code=-1,
                    command=command_str,
                )

            # Decode output
            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
            return_code = process.returncode or 0  # Handle None case

            result = CommandResult(
                success=(return_code == 0),
                stdout=stdout,
                stderr=stderr,
                return_code=return_code,
                command=command_str,
            )

            return result

        except Exception as e:
            error_msg = f"Unexpected error executing MC command: {str(e)}"
            logger.error(f"{error_msg} - Command: {command_str}")
            raise S3ManagerError(error_msg)
