"""Regression tests: web_scrape must block SSRF to private/internal networks."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import FastMCP

from aden_tools.tools.web_scrape_tool import register_tools
from aden_tools.tools.web_scrape_tool.web_scrape_tool import _resolves_to_private_ip


@pytest.fixture
def web_scrape_fn(mcp: FastMCP):
    """Register and return the web_scrape tool function."""
    register_tools(mcp)
    return mcp._tool_manager._tools["web_scrape"].fn


# ---------------------------------------------------------------------------
# Unit tests for the helper
# ---------------------------------------------------------------------------


class TestResolvesToPrivateIp:
    """_resolves_to_private_ip must identify internal addresses."""

    def test_loopback_ipv4(self):
        assert _resolves_to_private_ip("127.0.0.1") is True

    def test_localhost(self):
        assert _resolves_to_private_ip("localhost") is True

    def test_aws_metadata_endpoint(self):
        """169.254.169.254 is the AWS/GCP/Azure metadata service."""
        assert _resolves_to_private_ip("169.254.169.254") is True

    def test_rfc1918_class_a(self):
        assert _resolves_to_private_ip("10.0.0.1") is True

    def test_rfc1918_class_c(self):
        assert _resolves_to_private_ip("192.168.1.1") is True

    def test_unresolvable_hostname(self):
        """Hostnames that fail DNS resolution should not be flagged as private."""
        assert _resolves_to_private_ip("this-host-does-not-exist.invalid") is False

    @patch("aden_tools.tools.web_scrape_tool.web_scrape_tool.socket.getaddrinfo")
    def test_public_ip_allowed(self, mock_getaddrinfo):
        """Public IPs must not be blocked."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),  # example.com
        ]
        assert _resolves_to_private_ip("example.com") is False


# ---------------------------------------------------------------------------
# Integration tests: web_scrape blocks SSRF before launching the browser
# ---------------------------------------------------------------------------

_PRIVATE_IP_PATH = "aden_tools.tools.web_scrape_tool.web_scrape_tool._resolves_to_private_ip"
_PW_PATH = "aden_tools.tools.web_scrape_tool.web_scrape_tool.async_playwright"
_STEALTH_PATH = "aden_tools.tools.web_scrape_tool.web_scrape_tool.Stealth"


class TestWebScrapeSsrfProtection:
    """web_scrape must return an error for private IPs without launching a browser."""

    @pytest.mark.asyncio
    @patch(_PRIVATE_IP_PATH, return_value=True)
    async def test_localhost_blocked(self, mock_private, web_scrape_fn):
        result = await web_scrape_fn(url="http://127.0.0.1:8080/admin")
        assert result["skipped"] is True
        assert "private" in result["error"].lower()

    @pytest.mark.asyncio
    @patch(_PRIVATE_IP_PATH, return_value=True)
    async def test_aws_metadata_blocked(self, mock_private, web_scrape_fn):
        result = await web_scrape_fn(url="http://169.254.169.254/latest/meta-data/")
        assert result["skipped"] is True
        assert "private" in result["error"].lower()

    @pytest.mark.asyncio
    @patch(_PRIVATE_IP_PATH, return_value=True)
    async def test_internal_service_blocked(self, mock_private, web_scrape_fn):
        result = await web_scrape_fn(url="http://10.0.0.5:9200/_cluster/health")
        assert result["skipped"] is True

    @pytest.mark.asyncio
    @patch(_PRIVATE_IP_PATH, return_value=True)
    async def test_browser_never_launched_for_private_ip(self, mock_private, web_scrape_fn):
        """Playwright must NOT be started when the target is a private IP."""
        with patch(_PW_PATH) as mock_pw:
            await web_scrape_fn(url="http://192.168.1.1")
            mock_pw.assert_not_called()

    @pytest.mark.asyncio
    @patch(_STEALTH_PATH)
    @patch(_PW_PATH)
    @patch(_PRIVATE_IP_PATH, return_value=False)
    async def test_public_url_allowed(self, mock_private, mock_pw, mock_stealth, web_scrape_fn):
        """Public URLs must still work normally."""
        mock_response = MagicMock(
            status=200,
            url="https://example.com",
            headers={"content-type": "text/html"},
        )
        mock_page = AsyncMock()
        mock_page.goto.return_value = mock_response
        mock_page.content.return_value = "<html><body>Hello</body></html>"
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_pw_inst = MagicMock()
        mock_pw_inst.chromium.launch = AsyncMock(return_value=mock_browser)
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_pw_inst)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_pw.return_value = mock_cm
        mock_stealth.return_value.apply_stealth_async = AsyncMock()

        result = await web_scrape_fn(url="https://example.com")
        assert "error" not in result
