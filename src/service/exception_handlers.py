"""
Exception handlers for the FastAPI application.
"""

# copied from https://github.com/kbase/cdm-kube-spark-manager/blob/main/src/service/exception_handlers.py

import logging

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from service import errors
from service.error_mapping import map_error
from service.exceptions import S3Error
from service.models import ErrorResponse

logger = logging.getLogger(__name__)


def _format_error(
    status_code: int,
    error_code: int | None,
    error_type_str: str | None,
    message: str | None,
):
    """Format error response with consistent structure."""
    error_response = ErrorResponse(
        error=error_code,
        error_type=error_type_str,
        message=message or error_type_str or "Unknown error",
    )
    return JSONResponse(
        status_code=status_code,
        content=error_response.model_dump(),
    )


async def universal_error_handler(request: Request, exc: Exception):
    """
    Universal handler for all types of exceptions.

    Handles:
    - S3Error and its subclasses:
        - Authentication errors (MissingTokenError, InvalidTokenError, etc.)
        - MinIO specific errors (BucketOperationError, UserOperationError, etc.)
    - HTTPException from FastAPI
    - RequestValidationError for request validation
    - Generic exceptions
    """
    # Default values
    error_code = None
    error_type_str = None
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    if isinstance(exc, S3Error):
        # handle S3Error and subclasses
        error_type, status_code = map_error(exc)

        # Extract values from error_type if available
        if error_type:
            error_code = error_type.error_code
            error_type_str = error_type.error_type

        # Get the exception message, falling back to the error type string
        message = str(exc) if str(exc) else error_type_str

    elif isinstance(exc, RequestValidationError):
        # Handle validation errors from request parsing
        status_code = status.HTTP_400_BAD_REQUEST
        error_type_str = errors.ErrorType.REQUEST_VALIDATION_FAILED.error_type
        error_code = errors.ErrorType.REQUEST_VALIDATION_FAILED.error_code
        message = str(exc.errors())

    elif isinstance(exc, HTTPException):
        # handle FastAPI Exceptions
        status_code = exc.status_code
        message = str(exc.detail)

    else:
        # handle all other generic exceptions
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        message = "An unexpected error occurred"

    return _format_error(status_code, error_code, error_type_str, message)
