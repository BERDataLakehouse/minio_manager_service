"""
Health Check Tests.

Simple smoke tests to verify the service is running.
"""

import pytest


@pytest.mark.smoke
class TestHealthCheck:
    """Basic health check tests."""

    def test_health_endpoint(self, api_client):
        """
        Scenario:
            Request the health endpoint.
        Expected:
            - API returns 200
        Why this matters:
            Basic sanity check that service is running.
        """
        response = api_client.get("/health")
        assert response.status_code == 200
