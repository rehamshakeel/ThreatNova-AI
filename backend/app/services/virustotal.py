"""VirusTotal v3 REST API Integration Service.

Provides live threat reputation lookups for IP addresses, domains, file hashes, and URLs.
Includes rate-limit management, timeouts, error handling, and graceful unconfigured fallbacks.
"""

import base64
import logging
from typing import Any, Dict, List, Optional
import httpx
from app.config import settings
from app.schemas.investigation import IndicatorType, ReputationDataSchema, ReputationSourceSchema

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VTLookupResult:
    def __init__(
        self,
        configured: bool,
        status: str,  # live_success | not_found | rate_limited | invalid_key | network_error | unconfigured
        message: str,
        is_demo: bool = False,
        positives: int = 0,
        total: int = 0,
        malicious: bool = False,
        categories: Optional[List[str]] = None,
        sources: Optional[List[ReputationSourceSchema]] = None,
        raw_attributes: Optional[Dict[str, Any]] = None,
    ):
        self.configured = configured
        self.status = status
        self.message = message
        self.is_demo = is_demo
        self.positives = positives
        self.total = total
        self.malicious = malicious
        self.categories = categories or []
        self.sources = sources or []
        self.raw_attributes = raw_attributes or {}


def _get_demo_vt_result(indicator: str, indicator_type: IndicatorType) -> VTLookupResult:
    """Return clearly identified demo reputation fixtures when external API key is absent."""
    norm = indicator.lower()

    if "198.51.100.23" in norm or "dark-stealer" in norm or "c2" in norm:
        return VTLookupResult(
            configured=False,
            status="unconfigured",
            message="VirusTotal API key is not configured. Displaying simulated threat intelligence fixture.",
            is_demo=True,
            positives=7,
            total=90,
            malicious=True,
            categories=["C2 Server", "Phishing Infrastructure", "Stealer Relay"],
            sources=[
                ReputationSourceSchema(
                    name="VirusTotal (Demo Fixture)",
                    result="malicious",
                    detail="7/90 security vendors flagged as active C2 node [DEMO FIXTURE]",
                ),
                ReputationSourceSchema(
                    name="AlienVault OTX (Demo Fixture)",
                    result="malicious",
                    detail="Present in 4 threat intelligence pulses [DEMO FIXTURE]",
                ),
                ReputationSourceSchema(
                    name="AbuseIPDB (Demo Fixture)",
                    result="malicious",
                    detail="142 reports for automated brute-force reconnaissance [DEMO FIXTURE]",
                ),
                ReputationSourceSchema(
                    name="Google Safe Browsing (Demo Fixture)",
                    result="clean",
                    detail="No active malware distribution detected [DEMO FIXTURE]",
                ),
            ],
        )

    if "e3b0c442" in norm or "malware" in norm or "lockbit" in norm:
        return VTLookupResult(
            configured=False,
            status="unconfigured",
            message="VirusTotal API key is not configured. Displaying simulated threat intelligence fixture.",
            is_demo=True,
            positives=54,
            total=70,
            malicious=True,
            categories=["Ransomware Dropper", "Trojan.Generic", "LockBit 3.0"],
            sources=[
                ReputationSourceSchema(
                    name="VirusTotal (Demo Fixture)",
                    result="malicious",
                    detail="54/70 antivirus engines flagged executable sample [DEMO FIXTURE]",
                ),
                ReputationSourceSchema(
                    name="YARA Rule Match (Demo Fixture)",
                    result="malicious",
                    detail="Matched rule: SUSP_Lockbit_Ransomware_Strings [DEMO FIXTURE]",
                ),
            ],
        )

    if "clean" in norm or "safe" in norm:
        return VTLookupResult(
            configured=False,
            status="unconfigured",
            message="VirusTotal API key is not configured. Indicator matches simulated clean fixture.",
            is_demo=True,
            positives=0,
            total=88,
            malicious=False,
            categories=["Clean Infrastructure"],
            sources=[
                ReputationSourceSchema(
                    name="VirusTotal (Demo Fixture)",
                    result="clean",
                    detail="0/88 security engines detected threats [DEMO FIXTURE]",
                ),
            ],
        )

    # General neutral fallback
    return VTLookupResult(
        configured=False,
        status="unconfigured",
        message="Live VirusTotal lookup unavailable (VIRUSTOTAL_API_KEY is not set). No baseline records found.",
        is_demo=True,
        positives=0,
        total=0,
        malicious=False,
        categories=["Unrated / Telemetry Unavailable"],
        sources=[
            ReputationSourceSchema(
                name="VirusTotal",
                result="unknown",
                detail="External API key not configured; live telemetry lookup was skipped.",
            )
        ],
    )


async def lookup_virustotal(indicator: str, indicator_type: IndicatorType) -> VTLookupResult:
    """Query the VirusTotal v3 REST API with timeouts and graceful fallback."""
    api_key = settings.VIRUSTOTAL_API_KEY

    # If no API key configured, use clearly labeled demo or unavailable status
    if not api_key or not api_key.strip():
        logger.info(f"VirusTotal API key missing; utilizing fallback fixture for {indicator}")
        return _get_demo_vt_result(indicator, indicator_type)

    endpoint_map = {
        IndicatorType.IP: f"{VT_BASE_URL}/ip_addresses/{indicator}",
        IndicatorType.DOMAIN: f"{VT_BASE_URL}/domains/{indicator}",
        IndicatorType.HASH: f"{VT_BASE_URL}/files/{indicator}",
    }

    if indicator_type == IndicatorType.URL:
        # Base64-encode URL without padding as required by VT v3 API
        encoded_url = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("utf-8").strip("=")
        url = f"{VT_BASE_URL}/urls/{encoded_url}"
    elif indicator_type in endpoint_map:
        url = endpoint_map[indicator_type]
    else:
        # Usernames and emails are not directly queried via VT v3 endpoint
        return VTLookupResult(
            configured=True,
            status="unsupported_type",
            message=f"VirusTotal v3 does not offer direct reputation endpoints for {indicator_type.value}.",
            is_demo=False,
        )

    headers = {
        "x-apikey": api_key.strip(),
        "User-Agent": "ThreatNova-AI-Backend/1.0",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                harmless_count = stats.get("harmless", 0)
                undetected_count = stats.get("undetected", 0)
                total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

                is_malicious = malicious_count >= 3 or (malicious_count > 0 and suspicious_count > 0)

                # Extract vendor engine findings
                results = attributes.get("last_analysis_results", {})
                sources: List[ReputationSourceSchema] = []
                for engine_name, res in list(results.items())[:12]:
                    category = res.get("category", "unknown")
                    sources.append(
                        ReputationSourceSchema(
                            name=f"VirusTotal ({engine_name})",
                            result="malicious" if category == "malicious" else "suspicious" if category == "suspicious" else "clean",
                            detail=res.get("result") or f"Category: {category}",
                        )
                    )

                categories = attributes.get("categories", {})
                category_list = list(categories.values()) if isinstance(categories, dict) else []

                return VTLookupResult(
                    configured=True,
                    status="live_success",
                    message=f"Successfully queried VirusTotal v3 API. {malicious_count}/{total_engines} engines flagged.",
                    is_demo=False,
                    positives=malicious_count,
                    total=total_engines,
                    malicious=is_malicious,
                    categories=category_list or (["Malicious Indicator"] if is_malicious else ["Clean / Low Risk"]),
                    sources=sources,
                    raw_attributes=attributes,
                )

            elif response.status_code == 404:
                return VTLookupResult(
                    configured=True,
                    status="not_found",
                    message="Indicator not found in VirusTotal dataset (unseen across global telemetry).",
                    is_demo=False,
                )

            elif response.status_code == 401:
                logger.warning("VirusTotal API rejected key (401 Unauthorized)")
                return VTLookupResult(
                    configured=True,
                    status="invalid_key",
                    message="VirusTotal authentication failed: invalid API key.",
                    is_demo=False,
                )

            elif response.status_code == 429:
                logger.warning("VirusTotal API rate limit exceeded (429)")
                return VTLookupResult(
                    configured=True,
                    status="rate_limited",
                    message="VirusTotal API rate limit exceeded (quota full).",
                    is_demo=False,
                )

            else:
                return VTLookupResult(
                    configured=True,
                    status="api_error",
                    message=f"VirusTotal API returned HTTP {response.status_code}.",
                    is_demo=False,
                )

    except httpx.TimeoutException:
        logger.warning(f"VirusTotal API request timed out after {settings.REQUEST_TIMEOUT_SECONDS}s")
        return VTLookupResult(
            configured=True,
            status="network_error",
            message=f"Request to VirusTotal API timed out after {settings.REQUEST_TIMEOUT_SECONDS} seconds.",
            is_demo=False,
        )
    except Exception as exc:
        logger.error(f"Error querying VirusTotal API: {exc}", exc_info=True)
        return VTLookupResult(
            configured=True,
            status="network_error",
            message=f"Network error querying VirusTotal: {str(exc)}",
            is_demo=False,
        )
