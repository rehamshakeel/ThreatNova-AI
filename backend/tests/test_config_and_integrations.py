"""Tests for configuration validation, missing credentials, and mocked provider error handling.

Ensures zero live paid API calls during tests while rigorously validating all provider states.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import app
from app.services.integration_status import (
    check_llm_auth,
    check_virustotal_auth,
    get_integrations_health,
)

client = TestClient(app)


def test_settings_empty_keys_normalized_to_none():
    """Verify empty string API keys in environment are safely converted to None."""
    s = Settings(
        VIRUSTOTAL_API_KEY="   ",
        LLM_API_KEY="",
        LLM_MODEL="   ",
        LLM_PROVIDER="  ",
    )
    assert s.VIRUSTOTAL_API_KEY is None
    assert s.LLM_API_KEY is None
    assert s.LLM_MODEL is None
    assert s.LLM_PROVIDER == "none"


def test_settings_provider_normalization():
    """Verify provider names are lowercased and unknown providers safely default to none."""
    s1 = Settings(LLM_PROVIDER="OpenAI")
    assert s1.LLM_PROVIDER == "openai"

    s2 = Settings(LLM_PROVIDER="ANTHROPIC")
    assert s2.LLM_PROVIDER == "anthropic"

    s3 = Settings(LLM_PROVIDER="Gemini")
    assert s3.LLM_PROVIDER == "gemini"

    s4 = Settings(LLM_PROVIDER="invalid_unsupported_provider")
    assert s4.LLM_PROVIDER == "none"


@pytest.mark.anyio
async def test_virustotal_missing_key_status():
    """When VIRUSTOTAL_API_KEY is absent, status must be KEY MISSING with demo_fixture mode."""
    res = await check_virustotal_auth(api_key=None, verify_live=True)
    assert res.status == "KEY MISSING"
    assert res.configured is False
    assert res.authenticated is False
    assert res.mode == "demo_fixture"


@pytest.mark.anyio
async def test_virustotal_configured_not_verified():
    """When key exists but verify_live is False, status must be KEY CONFIGURED, NOT VERIFIED."""
    res = await check_virustotal_auth(api_key="mock-key-123", verify_live=False)
    assert res.status == "KEY CONFIGURED, NOT VERIFIED"
    assert res.configured is True
    assert res.authenticated is False


@pytest.mark.anyio
async def test_virustotal_mocked_auth_success():
    """Verify live authentication success handling via mocked HTTP 200 response."""
    mock_resp = MagicMock(status_code=200)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await check_virustotal_auth(api_key="valid-test-key", verify_live=True)
        assert res.status == "AUTHENTICATION SUCCESSFUL"
        assert res.authenticated is True
        assert res.configured is True


@pytest.mark.anyio
async def test_virustotal_mocked_unauthorized():
    """Verify invalid key handling via mocked HTTP 401 response."""
    mock_resp = MagicMock(status_code=401)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await check_virustotal_auth(api_key="invalid-test-key", verify_live=True)
        assert res.status == "INVALID KEY / UNAUTHORIZED"
        assert res.authenticated is False


@pytest.mark.anyio
async def test_virustotal_mocked_rate_limit():
    """Verify quota/rate limit handling via mocked HTTP 429 response."""
    mock_resp = MagicMock(status_code=429)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await check_virustotal_auth(api_key="exhausted-test-key", verify_live=True)
        assert res.status == "QUOTA OR RATE LIMIT EXCEEDED"
        assert res.authenticated is False


@pytest.mark.anyio
async def test_virustotal_mocked_timeout_network_error():
    """Verify network timeout error handling."""
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.TimeoutException("Connection timed out")
        res = await check_virustotal_auth(api_key="timeout-test-key", verify_live=True)
        assert res.status == "NETWORK OR PROVIDER ERROR"
        assert res.authenticated is False


@pytest.mark.anyio
async def test_llm_missing_key_status():
    """When LLM provider is none or key absent, status must be KEY MISSING with heuristic_fallback."""
    res = await check_llm_auth(provider="none", api_key=None, verify_live=True)
    assert res.status == "KEY MISSING"
    assert res.configured is False
    assert res.authenticated is False
    assert res.mode == "heuristic_fallback"


@pytest.mark.anyio
async def test_llm_mocked_openai_success():
    """Verify successful OpenAI authentication via mocked HTTP 200 response."""
    mock_resp = MagicMock(status_code=200)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await check_llm_auth(provider="openai", api_key="sk-test-key", verify_live=True)
        assert res.status == "AUTHENTICATION SUCCESSFUL"
        assert res.authenticated is True


@pytest.mark.anyio
async def test_llm_mocked_openai_unauthorized():
    """Verify OpenAI 401 Unauthorized handling."""
    mock_resp = MagicMock(status_code=401)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await check_llm_auth(provider="openai", api_key="sk-bad-key", verify_live=True)
        assert res.status == "INVALID KEY / UNAUTHORIZED"
        assert res.authenticated is False


@pytest.mark.anyio
async def test_llm_mocked_gemini_success():
    """Verify successful Gemini authentication via mocked HTTP 200 response."""
    mock_resp = MagicMock(status_code=200)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await check_llm_auth(provider="gemini", api_key="AIzaSyTest", verify_live=True)
        assert res.status == "AUTHENTICATION SUCCESSFUL"
        assert res.authenticated is True


def test_health_endpoint_integrations_reporting():
    """Verify GET /health contains integrations status dictionary."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "integrations" in data
    assert "virustotal" in data["integrations"]
    assert "llm" in data["integrations"]
    # Confirm secrets are never leaked as dictionary fields
    assert "api_key" not in data
    assert "token" not in data
    assert "secret" not in data
    assert "key" not in data["integrations"]["virustotal"]
    assert "key" not in data["integrations"]["llm"]


def test_health_integrations_endpoint():
    """Verify GET /api/health/integrations returns structured statuses."""
    resp = client.get("/api/health/integrations?verify=false")
    assert resp.status_code == 200
    data = resp.json()
    assert "virustotal" in data
    assert "llm" in data
    assert data["virustotal"]["status"] in [
        "KEY MISSING",
        "KEY CONFIGURED, NOT VERIFIED",
        "AUTHENTICATION SUCCESSFUL",
    ]
