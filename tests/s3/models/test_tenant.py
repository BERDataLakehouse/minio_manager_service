"""Tests for tenant Pydantic models — website URL validation."""

import pytest
from pydantic import ValidationError

from src.s3.models.tenant import TenantMetadataUpdate


class TestWebsiteValidation:
    def test_accepts_https(self):
        m = TenantMetadataUpdate(website="https://example.com")
        assert m.website == "https://example.com"

    def test_accepts_http(self):
        m = TenantMetadataUpdate(website="http://example.com")
        assert m.website == "http://example.com"

    def test_accepts_none(self):
        m = TenantMetadataUpdate(website=None)
        assert m.website is None

    def test_accepts_omitted(self):
        m = TenantMetadataUpdate(display_name="X")
        assert m.website is None

    def test_rejects_javascript_scheme(self):
        with pytest.raises(ValidationError):
            TenantMetadataUpdate(website="javascript:alert(1)")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValidationError):
            TenantMetadataUpdate(website="ftp://example.com")

    def test_rejects_data_uri(self):
        with pytest.raises(ValidationError):
            TenantMetadataUpdate(website="data:text/html,<h1>hi</h1>")

    def test_rejects_bare_string(self):
        with pytest.raises(ValidationError):
            TenantMetadataUpdate(website="not-a-url")

    def test_rejects_too_long(self):
        with pytest.raises(ValidationError):
            TenantMetadataUpdate(website="https://example.com/" + "a" * 2048)

    def test_accepts_url_with_path_and_query(self):
        url = "https://example.com/path?q=1&r=2#frag"
        m = TenantMetadataUpdate(website=url)
        assert m.website == url
