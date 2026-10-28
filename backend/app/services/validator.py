"""Validation and normalization service for cybersecurity indicators."""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse
from app.schemas.investigation import IndicatorType


# Regex definitions matching frontend lib/indicators.ts bounds
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
HASH_HEX_REGEX = re.compile(r"^[a-fA-F0-9]+$")


def normalize_indicator(query: str, indicator_type: Optional[IndicatorType] = None) -> Tuple[str, IndicatorType]:
    """Validate, clean, normalize indicator, and detect its type if not provided.

    Returns:
        Tuple[str, IndicatorType]: (normalized_query, resolved_type)

    Raises:
        ValueError: with clear explanation if input is invalid.
    """
    cleaned = query.strip()
    if not cleaned:
        raise ValueError("Indicator query cannot be empty.")

    # Auto-detect type if not explicitly supplied
    detected_type = indicator_type or detect_indicator_type(cleaned)
    if not detected_type:
        raise ValueError(
            f"Unrecognized indicator format for '{cleaned}'. "
            "Expected IPv4/IPv6, domain, URL, file hash (MD5/SHA1/SHA256/SHA512), email, or username."
        )

    # Validate against specific type
    if detected_type == IndicatorType.IP:
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            return str(ip_obj), IndicatorType.IP
        except ValueError:
            raise ValueError(f"'{cleaned}' is not a valid IPv4 or IPv6 address.")

    elif detected_type == IndicatorType.DOMAIN:
        # Strip trailing dot if present
        domain = cleaned[:-1] if cleaned.endswith(".") else cleaned
        domain = domain.lower()
        if not DOMAIN_REGEX.match(domain):
            raise ValueError(f"'{cleaned}' is not a valid RFC-compliant domain name.")
        return domain, IndicatorType.DOMAIN

    elif detected_type == IndicatorType.URL:
        # Prepend scheme if missing for parsing
        test_url = cleaned if "://" in cleaned else f"http://{cleaned}"
        try:
            parsed = urlparse(test_url)
            if not parsed.hostname:
                raise ValueError
            # Canonicalize protocol to lowercase and preserve full path
            return cleaned, IndicatorType.URL
        except Exception:
            raise ValueError(f"'{cleaned}' is not a valid URL.")

    elif detected_type == IndicatorType.HASH:
        norm_hash = cleaned.lower()
        length = len(norm_hash)
        if length not in (32, 40, 64, 128) or not HASH_HEX_REGEX.match(norm_hash):
            raise ValueError(
                f"'{cleaned}' is not a valid cryptographic hash. "
                "Accepted formats: MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex), or SHA-512 (128 hex)."
            )
        return norm_hash, IndicatorType.HASH

    elif detected_type == IndicatorType.EMAIL:
        norm_email = cleaned.lower()
        if not EMAIL_REGEX.match(norm_email):
            raise ValueError(f"'{cleaned}' is not a valid email address.")
        return norm_email, IndicatorType.EMAIL

    elif detected_type == IndicatorType.USERNAME:
        if not USERNAME_REGEX.match(cleaned):
            raise ValueError(
                f"'{cleaned}' is not a valid username (3-32 alphanumeric characters, '.', '_', or '-')."
            )
        return cleaned, IndicatorType.USERNAME

    raise ValueError(f"Unsupported indicator type: {detected_type}")


def detect_indicator_type(value: str) -> Optional[IndicatorType]:
    """Detect indicator type based on syntax and pattern heuristic analysis."""
    trimmed = value.strip()
    if not trimmed:
        return None

    # 1. IP check
    try:
        ipaddress.ip_address(trimmed)
        return IndicatorType.IP
    except ValueError:
        pass

    # 2. Cryptographic Hash check
    if HASH_HEX_REGEX.match(trimmed) and len(trimmed) in (32, 40, 64, 128):
        return IndicatorType.HASH

    # 3. URL check
    if trimmed.startswith(("http://", "https://", "ftp://")) or (
        "/" in trimmed and DOMAIN_REGEX.match(trimmed.split("/")[0])
    ):
        return IndicatorType.URL

    # 4. Email check
    if "@" in trimmed and EMAIL_REGEX.match(trimmed):
        return IndicatorType.EMAIL

    # 5. Domain check
    domain_candidate = trimmed[:-1] if trimmed.endswith(".") else trimmed
    if DOMAIN_REGEX.match(domain_candidate.lower()):
        return IndicatorType.DOMAIN

    # 6. Username check (if no dot or slash and matches handle regex)
    if USERNAME_REGEX.match(trimmed) and "." not in trimmed and "/" not in trimmed:
        return IndicatorType.USERNAME

    return None
