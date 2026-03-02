"""Tests for the exception_handlers module."""

import pytest
from unittest.mock import MagicMock

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError

from src.service.exception_handlers import _format_error, universal_error_handler
from src.service.exceptions import (
    InvalidTokenError,
    MissingTokenError,
    PolicyOperationError,
    UserOperationError,
)


# === FORMAT ERROR TESTS ===


class TestFormatError:
    """Tests for _format_error helper."""

    def test_format_error_basic(self):
        """Test basic error formatting."""
        response = _format_error(400, 10000, "Bad Request", "Something went wrong")
        assert response.status_code == 400
        body = response.body
        assert b"Something went wrong" in body

    def test_format_error_none_message_uses_error_type(self):
        """Test None message falls back to error_type_str."""
        response = _format_error(500, 20000, "Server Error", None)
        assert b"Server Error" in response.body

    def test_format_error_all_none(self):
        """Test all-None values produce 'Unknown error'."""
        response = _format_error(500, None, None, None)
        assert b"Unknown error" in response.body


# === UNIVERSAL ERROR HANDLER TESTS ===


class TestUniversalErrorHandler:
    """Tests for universal_error_handler."""

    @pytest.fixture
    def mock_request(self):
        return MagicMock()

    @pytest.mark.asyncio
    async def test_handle_missing_token_error(self, mock_request):
        """Test MissingTokenError maps to 401."""
        exc = MissingTokenError("No token")
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_handle_invalid_token_error(self, mock_request):
        """Test InvalidTokenError maps to 401."""
        exc = InvalidTokenError("Bad token")
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_handle_policy_operation_error(self, mock_request):
        """Test PolicyOperationError maps to 500."""
        exc = PolicyOperationError("Policy failed")
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 500

    @pytest.mark.asyncio
    async def test_handle_user_operation_error(self, mock_request):
        """Test UserOperationError maps to 400."""
        exc = UserOperationError("User error")
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_handle_http_exception(self, mock_request):
        """Test HTTPException is handled correctly."""
        exc = HTTPException(status_code=404, detail="Not found")
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 404
        assert b"Not found" in response.body

    @pytest.mark.asyncio
    async def test_handle_request_validation_error(self, mock_request):
        """Test RequestValidationError maps to 400."""
        exc = RequestValidationError(
            errors=[
                {"loc": ["body", "name"], "msg": "field required", "type": "missing"}
            ]
        )
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_handle_generic_exception(self, mock_request):
        """Test generic Exception maps to 500."""
        exc = RuntimeError("Something unexpected")
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 500
        assert b"An unexpected error occurred" in response.body

    @pytest.mark.asyncio
    async def test_minio_error_includes_error_code(self, mock_request):
        """Test MinIOError response includes error code from mapping."""
        exc = MissingTokenError("Authorization header required")
        response = await universal_error_handler(mock_request, exc)
        assert response.status_code == 401
        # Verify the response body contains the error code
        assert b"10010" in response.body  # NO_TOKEN error code
