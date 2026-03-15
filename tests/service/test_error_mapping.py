"""Tests for the error_mapping module."""

from fastapi import status

from src.service.error_mapping import map_error
from src.service.errors import ErrorType
from src.service.exceptions import (
    MinIOError,
    MissingTokenError,
    ValidationError,
)


def test_error_mapping_imports():
    """Test that error_mapping module can be imported."""
    from src.service import error_mapping

    assert error_mapping is not None


def test_map_known_error():
    """Test map_error returns correct mapping for a known error type."""
    err = MissingTokenError("no token")
    mapping = map_error(err)
    assert mapping.err_type == ErrorType.NO_TOKEN
    assert mapping.http_code == status.HTTP_401_UNAUTHORIZED


def test_map_validation_error():
    """Test map_error for ValidationError."""
    err = ValidationError("bad input")
    mapping = map_error(err)
    assert mapping.err_type == ErrorType.VALIDATION_ERROR
    assert mapping.http_code == status.HTTP_400_BAD_REQUEST


def test_map_base_minio_error():
    """Test map_error for the base MinIOError class."""
    err = MinIOError("generic error")
    mapping = map_error(err)
    assert mapping.err_type == ErrorType.MINIO_ERROR
    assert mapping.http_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_map_unknown_error_returns_500_fallback():
    """Test map_error with an unmapped subclass returns 500 fallback (covers line 83)."""

    class UnknownMinIOSubclass(MinIOError):
        """An error subclass not registered in _ERR_MAP."""

        pass

    err = UnknownMinIOSubclass("surprise error")
    mapping = map_error(err)
    assert mapping.err_type is None
    assert mapping.http_code == status.HTTP_500_INTERNAL_SERVER_ERROR
