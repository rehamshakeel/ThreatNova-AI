"""Tests for indicator normalization and validation service."""

import pytest
from app.schemas.investigation import IndicatorType
from app.services.validator import detect_indicator_type, normalize_indicator


def test_ip_validation():
    norm, resolved = normalize_indicator(" 198.51.100.23 ")
    assert norm == "198.51.100.23"
    assert resolved == IndicatorType.IP

    with pytest.raises(ValueError, match="not a valid IPv4 or IPv6"):
        normalize_indicator("999.999.999.999", IndicatorType.IP)


def test_domain_validation():
    norm, resolved = normalize_indicator("DARK-STEALER-C2.NET.")
    assert norm == "dark-stealer-c2.net"
    assert resolved == IndicatorType.DOMAIN

    with pytest.raises(ValueError, match="not a valid RFC-compliant domain"):
        normalize_indicator("invalid_domain_name", IndicatorType.DOMAIN)


def test_hash_validation():
    valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    norm, resolved = normalize_indicator(valid_sha256)
    assert norm == valid_sha256
    assert resolved == IndicatorType.HASH

    with pytest.raises(ValueError, match="not a valid cryptographic hash"):
        normalize_indicator("badhash123", IndicatorType.HASH)


def test_url_validation():
    norm, resolved = normalize_indicator("https://phishing-portal.live/login?session=1")
    assert resolved == IndicatorType.URL
    assert "phishing-portal.live" in norm


def test_email_validation():
    norm, resolved = normalize_indicator("threat-actor@c2-ops.net")
    assert norm == "threat-actor@c2-ops.net"
    assert resolved == IndicatorType.EMAIL


def test_username_validation():
    norm, resolved = normalize_indicator("apt_operator-01", IndicatorType.USERNAME)
    assert norm == "apt_operator-01"
    assert resolved == IndicatorType.USERNAME


def test_empty_input_rejection():
    with pytest.raises(ValueError, match="cannot be empty"):
        normalize_indicator("   ")
