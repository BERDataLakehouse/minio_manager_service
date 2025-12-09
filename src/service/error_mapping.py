"""
Map errors from exception type to custom error type and HTTP status.
"""

# mostly copied from https://github.com/kbase/cdm-task-service/blob/main/cdmtaskservice/error_mapping.py

from typing import NamedTuple

from fastapi import status

from src.service.errors import ErrorType
from src.service.exceptions import (  # MinIO specific exceptions
    AuthenticationError,
    BucketOperationError,
    BucketValidationError,
    ConnectionError,
    DataGovernanceError,
    GroupOperationError,
    InvalidAuthHeaderError,
    InvalidTokenError,
    MinIOError,
    MinIOManagerError,
    MissingRoleError,
    MissingTokenError,
    PolicyOperationError,
    PolicyValidationError,
    UserOperationError,
    ValidationError,
)

_H400 = status.HTTP_400_BAD_REQUEST
_H401 = status.HTTP_401_UNAUTHORIZED
_H403 = status.HTTP_403_FORBIDDEN
_H404 = status.HTTP_404_NOT_FOUND
_H409 = status.HTTP_409_CONFLICT
_H500 = status.HTTP_500_INTERNAL_SERVER_ERROR
_H503 = status.HTTP_503_SERVICE_UNAVAILABLE


class ErrorMapping(NamedTuple):
    """The application error type and HTTP status code for an exception."""

    err_type: ErrorType | None
    """ The type of application error. None if a 5XX error or Not Found."""
    http_code: int
    """ The HTTP code of the error. """


# Map only using ErrorTypes that actually exist in errors.py
_ERR_MAP = {
    # Authentication errors
    MissingTokenError: ErrorMapping(ErrorType.NO_TOKEN, _H401),
    InvalidAuthHeaderError: ErrorMapping(ErrorType.INVALID_AUTH_HEADER, _H401),
    InvalidTokenError: ErrorMapping(ErrorType.INVALID_TOKEN, _H401),
    MissingRoleError: ErrorMapping(ErrorType.MISSING_ROLE, _H403),
    AuthenticationError: ErrorMapping(ErrorType.AUTHENTICATION_FAILED, _H401),
    # MinIO specific errors
    MinIOManagerError: ErrorMapping(ErrorType.MINIO_MANAGER_ERROR, _H500),
    PolicyValidationError: ErrorMapping(ErrorType.POLICY_VALIDATION_ERROR, _H400),
    PolicyOperationError: ErrorMapping(ErrorType.POLICY_OPERATION_ERROR, _H500),
    BucketOperationError: ErrorMapping(ErrorType.BUCKET_OPERATION_ERROR, _H500),
    UserOperationError: ErrorMapping(ErrorType.USER_OPERATION_ERROR, _H400),
    GroupOperationError: ErrorMapping(ErrorType.GROUP_OPERATION_ERROR, _H400),
    DataGovernanceError: ErrorMapping(ErrorType.DATA_GOVERNANCE_ERROR, _H403),
    ConnectionError: ErrorMapping(ErrorType.CONNECTION_ERROR, _H503),
    # Base error fallback
    MinIOError: ErrorMapping(ErrorType.MINIO_ERROR, _H500),
}


def map_error(err: MinIOError) -> ErrorMapping:
    """
    Map an error to an optional error type and a HTTP code.
    """
    # May need to add code to go up the error hierarchy if multiple errors have the same type
    mapping = _ERR_MAP.get(type(err))

    if not mapping:
        mapping = ErrorMapping(None, status.HTTP_500_INTERNAL_SERVER_ERROR)

    return mapping
