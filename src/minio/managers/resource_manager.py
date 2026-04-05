"""
Generic Resource Manager for eliminating CRUD duplication.

This module provides a generic base class that abstracts common resource
management patterns across different MinIO resource types (users, groups, policies, etc.).
"""

import logging
import os
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncIterator, Generic, List, Optional, TypeVar

from service.exceptions import S3ManagerError
from minio.core.base_executor import BaseMinIOExecutor
from minio.core.command_builder import MinIOCommandBuilder
from s3.core.s3_client import S3Client
from s3.models.s3_config import S3Config

# Generic type for resource models
T = TypeVar("T")

logger = logging.getLogger(__name__)

DEFAULT_ALIAS = "minio_api"


class ResourceManager(ABC, Generic[T]):
    """
    Generic base class for MinIO resource management.

    This class provides common CRUD operations and patterns that are shared
    across different resource types (users, groups, policies, etc.).

    Type parameter T represents the resource model type (UserModel, GroupModel, etc.).
    """

    def __init__(
        self,
        client: S3Client,
        config: S3Config,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        """Initialize the resource manager.

        Args:
            client: Async S3 client instance
            config: S3 configuration
            logger_instance: Optional logger instance
        """
        self.client = client
        self.config = config
        self.logger = logger_instance or logging.getLogger(self.__class__.__name__)

        # Initialize executor and command infrastructure
        self._executor = BaseMinIOExecutor(config)
        self.alias = os.environ.get("MINIO_API_ALIAS", DEFAULT_ALIAS)
        self._command_builder = MinIOCommandBuilder(self.alias)

    async def ensure_executor_setup(self) -> None:
        """Ensure the MC executor is properly set up."""
        await self._executor.setup()

    @asynccontextmanager
    async def operation_context(self, operation: str) -> AsyncIterator[None]:
        """
        Async context manager for operations with logging and error handling.

        Args:
            operation: Name of the operation
        """
        self.logger.info(f"Starting {operation}")

        try:
            # Ensure executor is set up for MC operations
            await self.ensure_executor_setup()
            yield
            self.logger.info(f"Completed {operation}")
        except Exception as e:
            self.logger.error(f"Failed {operation}: {e}")
            # Re-raise with appropriate MinIO exception type
            if isinstance(e, S3ManagerError):
                raise
            else:
                raise S3ManagerError(f"{operation} failed: {str(e)}") from e

    # === Abstract Methods (must be implemented by subclasses) ===

    @abstractmethod
    def _get_resource_type(self) -> str:
        """Get the resource type name (e.g., 'user', 'group', 'policy')."""
        pass

    @abstractmethod
    def _validate_resource_name(self, name: str) -> str:
        """
        Validate and normalize a resource name.

        Args:
            name: Resource name to validate

        Returns:
            Validated and normalized name

        Raises:
            ValueError: If name is invalid
        """
        pass

    @abstractmethod
    def _build_exists_command(self, name: str) -> List[str]:
        """
        Build command to check if resource exists.

        Args:
            name: Resource name

        Returns:
            Command arguments list
        """
        pass

    @abstractmethod
    def _build_list_command(self) -> List[str]:
        """
        Build command to list all resources.

        Returns:
            Command arguments list
        """
        pass

    @abstractmethod
    def _build_delete_command(self, name: str) -> List[str]:
        """
        Build command to delete a resource.

        Args:
            name: Resource name

        Returns:
            Command arguments list
        """
        pass

    @abstractmethod
    def _parse_list_output(self, stdout: str) -> List[str]:
        """
        Parse command output to extract resource names.

        Args:
            stdout: Command output

        Returns:
            List of resource names
        """
        pass

    # === Generic CRUD Operations ===

    async def resource_exists(self, name: str) -> bool:
        """
        Check if a resource exists.

        Args:
            name: Resource name

        Returns:
            True if resource exists, False otherwise
        """
        async with self.operation_context(f"check_{self._get_resource_type()}_exists"):
            try:
                validated_name = self._validate_resource_name(name)
                cmd_args = self._build_exists_command(validated_name)
                result = await self._executor._execute_command(cmd_args)
                return result.success
            except Exception as e:
                self.logger.warning(
                    f"Error checking if {self._get_resource_type()} {name} exists: {e}"
                )
                return False

    async def list_resources(self, name_filter: Optional[str] = None) -> List[str]:
        """
        List all resources with optional filtering.

        Args:
            name_filter: Optional filter to apply to resource names

        Returns:
            List of resource names
        """
        async with self.operation_context(f"list_{self._get_resource_type()}s"):
            try:
                cmd_args = self._build_list_command()
                result = await self._executor._execute_command(cmd_args)

                if not result.success:
                    self.logger.warning(
                        f"Failed to list {self._get_resource_type()}s: {result.stderr}"
                    )
                    return []

                resource_names = self._parse_list_output(result.stdout)

                # Apply name filter if provided
                if name_filter:
                    resource_names = [
                        name
                        for name in resource_names
                        if name_filter.lower() in name.lower()
                    ]

                self.logger.info(
                    f"Found {len(resource_names)} {self._get_resource_type()}s"
                )
                return sorted(resource_names)

            except Exception as e:
                self.logger.error(f"Error listing {self._get_resource_type()}s: {e}")
                return []

    async def delete_resource(self, name: str, force: bool = False) -> bool:
        """
        Delete a resource.

        Args:
            name: Resource name
            force: Force deletion even if resource has dependencies

        Returns:
            True if successfully deleted, False otherwise
        """
        async with self.operation_context(f"delete_{self._get_resource_type()}"):
            try:
                validated_name = self._validate_resource_name(name)

                # Check if resource exists before attempting deletion
                if not await self.resource_exists(validated_name):
                    self.logger.warning(
                        f"{self._get_resource_type().title()} {validated_name} does not exist"
                    )
                    return False

                # Perform pre-deletion cleanup if needed
                await self._pre_delete_cleanup(validated_name, force)

                # Execute delete command
                cmd_args = self._build_delete_command(validated_name)
                result = await self._executor._execute_command(cmd_args)

                if not result.success:
                    self.logger.error(
                        f"Failed to delete {self._get_resource_type()} {validated_name}: {result.stderr}"
                    )
                    return False

                # Perform post-deletion cleanup if needed
                await self._post_delete_cleanup(validated_name)

                self.logger.info(
                    f"Successfully deleted {self._get_resource_type()} {validated_name}"
                )
                return True

            except Exception as e:
                self.logger.error(
                    f"Error deleting {self._get_resource_type()} {name}: {e}"
                )
                return False

    # === Helper Methods ===

    async def _pre_delete_cleanup(self, name: str, force: bool = False) -> None:
        """
        Perform any necessary cleanup before deleting a resource.

        Subclasses can override this to implement specific cleanup logic.

        Args:
            name: Resource name
            force: Whether to force cleanup
        """
        pass

    async def _post_delete_cleanup(self, name: str) -> None:
        """
        Perform any necessary cleanup after deleting a resource.

        Subclasses can override this to implement specific cleanup logic.

        Args:
            name: Resource name
        """
        pass
