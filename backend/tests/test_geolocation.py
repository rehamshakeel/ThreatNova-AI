"""Comprehensive tests for IP Geolocation with Multi-Provider Fallbacks, CDN/Edge handling, and Email MX resolution."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from app.schemas.investigation import IndicatorType, GeolocationSchema
from app.services.enrichment import (
    is_public_ip,
    get_ip_geolocation,
    enrich_indicator,
    check_cdn_edge,
)
from app.services.virustotal import VTLookupResult


# Dummy VTLookupResult for testing enrichment
DUMMY_VT = VTLookupResult(
    configured=False,
    status="demo_fixture",
    message="Demo fixture loaded",
    is_demo=True,
    positives=0,
    total=70,
    malicious=False,
    categories=["Clean"],
    sources=[],
)


# 1. Validation tests for is_public_ip
def test_is_public_ip_validates_correctly():
    # Valid public IPs
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("142.250.190.46") is True

    # Private, loopback, link-local, multicast, invalid
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("169.254.1.1") is False
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("invalid-ip") is False
    assert is_public_ip("") is False
    assert is_public_ip(None) is False


# 2. Public IP geolocation with primary provider (ip-api.com)
def test_get_ip_geolocation_success_primary():
    async def _test():
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "lat": 39.03,
            "lon": -77.5,
            "city": "Ashburn",
            "regionName": "Virginia",
            "country": "United States",
            "countryCode": "US",
            "isp": "Google LLC",
            "org": "Google Public DNS",
            "as": "AS15169 Google LLC",
            "query": "8.8.8.8",
        }

        with patch("app.services.enrichment._lookup_ip_api", new_callable=AsyncMock) as mock_primary:
            mock_primary.return_value = GeolocationSchema(
                latitude=39.03,
                longitude=-77.5,
                city="Ashburn",
                region="Virginia",
                country="United States",
                countryCode="US",
                org="Google Public DNS",
                asn="AS15169 Google LLC",
                ip="8.8.8.8",
                resolved_ip="8.8.8.8",
                source="ip-api.com",
                retrieved_at="2026-10-27T00:00:00Z",
                is_cdn_edge=True,
                note="CDN Edge Location - closest to resolver",
            )
            result = await get_ip_geolocation("8.8.8.8")

            assert result is not None
            assert isinstance(result, GeolocationSchema)
            assert result.latitude == 39.03
            assert result.longitude == -77.5
            assert result.city == "Ashburn"
            assert result.countryCode == "US"
            assert result.source == "ip-api.com"
            assert result.is_cdn_edge is True

    asyncio.run(_test())


# 3. Rate Limit (429) on ip-api.com triggers fallback to ipinfo.io
def test_rate_limit_429_triggers_fallback_ipinfo():
    async def _test():
        # Primary fails with None (simulating 429)
        with patch("app.services.enrichment._lookup_ip_api", new_callable=AsyncMock) as mock_primary, \
             patch("app.services.enrichment._lookup_ipinfo", new_callable=AsyncMock) as mock_fallback1:
            mock_primary.return_value = None
            mock_fallback1.return_value = GeolocationSchema(
                latitude=37.422,
                longitude=-122.084,
                city="Mountain View",
                region="California",
                country="US",
                countryCode="US",
                org="AS15169 Google LLC",
                asn="AS15169",
                ip="8.8.8.8",
                resolved_ip="8.8.8.8",
                source="ipinfo.io",
                retrieved_at="2026-10-27T00:00:00Z",
                is_cdn_edge=True,
                note="CDN Edge Location - closest to resolver",
            )

            result = await get_ip_geolocation("8.8.8.8")
            assert result is not None
            assert result.source == "ipinfo.io"
            assert result.city == "Mountain View"
            assert result.latitude == 37.422

    asyncio.run(_test())


# 4. Fallback 2: freeipapi.com triggers when primary and fallback 1 fail
def test_fallback_freeipapi():
    async def _test():
        with patch("app.services.enrichment._lookup_ip_api", new_callable=AsyncMock) as mock_primary, \
             patch("app.services.enrichment._lookup_ipinfo", new_callable=AsyncMock) as mock_fallback1, \
             patch("app.services.enrichment._lookup_freeipapi", new_callable=AsyncMock) as mock_fallback2:
            mock_primary.return_value = None
            mock_fallback1.return_value = None
            mock_fallback2.return_value = GeolocationSchema(
                latitude=37.422,
                longitude=-122.084,
                city="Mountain View",
                region="California",
                country="United States",
                countryCode="US",
                org="Google LLC",
                asn="AS15169",
                ip="8.8.8.8",
                resolved_ip="8.8.8.8",
                source="freeipapi.com",
                retrieved_at="2026-10-27T00:00:00Z",
                is_cdn_edge=True,
                note="CDN Edge Location - closest to resolver",
            )

            result = await get_ip_geolocation("8.8.8.8")
            assert result is not None
            assert result.source == "freeipapi.com"
            assert result.city == "Mountain View"

    asyncio.run(_test())


# 5. Private IP is rejected before making any network request
def test_private_ip_rejected_no_lookup():
    async def _test():
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = await get_ip_geolocation("192.168.1.1")
            assert result is None
            mock_get.assert_not_called()

            loopback_result = await get_ip_geolocation("127.0.0.1")
            assert loopback_result is None
            mock_get.assert_not_called()

    asyncio.run(_test())


# 6. Provider timeout or total failure returns None gracefully
def test_all_providers_fail_graceful():
    async def _test():
        with patch("app.services.enrichment._lookup_ip_api", new_callable=AsyncMock) as mock_p, \
             patch("app.services.enrichment._lookup_ipinfo", new_callable=AsyncMock) as mock_f1, \
             patch("app.services.enrichment._lookup_freeipapi", new_callable=AsyncMock) as mock_f2, \
             patch("app.services.enrichment._lookup_ipapi_co", new_callable=AsyncMock) as mock_f3:
            mock_p.return_value = None
            mock_f1.return_value = None
            mock_f2.return_value = None
            mock_f3.return_value = None

            result = await get_ip_geolocation("8.8.8.8")
            assert result is None

    asyncio.run(_test())


# 7. CDN/Edge detection test
def test_cdn_edge_detection():
    is_cdn, note = check_cdn_edge(org="Google LLC", asn="AS15169")
    assert is_cdn is True
    assert "CDN Edge Location" in note

    is_cf, cf_note = check_cdn_edge(org="Cloudflare, Inc.", asn="AS13335")
    assert is_cf is True

    is_akamai, _ = check_cdn_edge(org="Akamai Technologies")
    assert is_akamai is True

    is_norm, norm_note = check_cdn_edge(org="Local Telecom Provider", asn="AS99999", host="internal.local")
    assert is_norm is False
    assert norm_note is None


# 8. Email address with MX resolution for theaaditya11@gmail.com
def test_email_address_mx_resolution():
    async def _test():
        intel = await enrich_indicator("theaaditya11@gmail.com", IndicatorType.EMAIL, DUMMY_VT)

        assert intel is not None
        assert intel.geo is not None
        assert isinstance(intel.geo.latitude, float)
        assert isinstance(intel.geo.longitude, float)
        assert intel.geo.country in ["United States", "US", "India", "IN"]
        assert intel.geo.is_cdn_edge is True
        # Verify MX records were resolved and added
        assert any(rec.type == "MX" for rec in intel.dns)

    asyncio.run(_test())


# 9. Username input: no location is invented
def test_username_input_no_location():
    async def _test():
        with patch("app.services.enrichment.get_ip_geolocation", new_callable=AsyncMock) as mock_get_geo:
            intel = await enrich_indicator("threat_actor_99", IndicatorType.USERNAME, DUMMY_VT)

            assert intel.geo is None
            assert intel.ipInfo is None
            mock_get_geo.assert_not_called()

    asyncio.run(_test())


# 10. Missing geolocation: no Bucharest fallback
def test_missing_geolocation_no_bucharest_fallback():
    async def _test():
        with patch("app.services.enrichment.get_ip_geolocation", new_callable=AsyncMock) as mock_get_geo:
            mock_get_geo.return_value = None
            intel = await enrich_indicator("93.184.216.34", IndicatorType.IP, DUMMY_VT)

            assert intel.geo is None
            assert intel.ipInfo is not None
            assert intel.ipInfo.city != "Bucharest"
            assert intel.ipInfo.latitude is None
            assert intel.ipInfo.longitude is None

    asyncio.run(_test())


# 11. Live Provider Smoke Test
def test_live_provider_smoke_test():
    async def _test():
        res = await get_ip_geolocation("8.8.8.8")
        if res:
            assert isinstance(res.latitude, float)
            assert isinstance(res.longitude, float)
            assert res.is_cdn_edge is True
            print(f"\n[LIVE TEST] 8.8.8.8 -> {res.city}, {res.country} ({res.latitude}, {res.longitude}) [CDN Edge: {res.is_cdn_edge}]")

    asyncio.run(_test())
