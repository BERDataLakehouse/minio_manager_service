"""
Health check routes for the API.
"""

from typing import Annotated

from fastapi import APIRouter
from pydantic import BaseModel, Field

# Create a router for health endpoints
router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Health check response model."""

    status: Annotated[str, Field(description="Health status")]


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns the health status of the API.",
)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="healthy")
