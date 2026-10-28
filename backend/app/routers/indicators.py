"""Quick indicator validation and intelligence lookup endpoint."""

from fastapi import APIRouter, HTTPException, status
from app.schemas.investigation import IndicatorType
from app.services.enrichment import enrich_indicator
from app.services.validator import normalize_indicator
from app.services.virustotal import lookup_virustotal

router = APIRouter(prefix="/api/indicators", tags=["Indicators"])


@router.get("/{indicator_type}/{value}")
async def quick_indicator_lookup(indicator_type: str, value: str):
    """Perform on-demand validation and threat intelligence inspection for an indicator."""
    try:
        enum_type = IndicatorType(indicator_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid indicator type '{indicator_type}'. Allowed types: {[t.value for t in IndicatorType]}",
        )

    try:
        norm_query, resolved_type = normalize_indicator(value, enum_type)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )

    vt_result = await lookup_virustotal(norm_query, resolved_type)
    domain_intel = await enrich_indicator(norm_query, resolved_type, vt_result)

    return {
        "indicator": norm_query,
        "type": resolved_type.value,
        "valid": True,
        "reputation": {
            "malicious": vt_result.malicious,
            "positives": vt_result.positives,
            "total": vt_result.total,
            "status": vt_result.status,
            "isDemo": vt_result.is_demo,
            "categories": vt_result.categories,
        },
        "network": {
            "resolvedIp": domain_intel.ipInfo.ip if domain_intel.ipInfo else None,
            "asn": domain_intel.ipInfo.asn if domain_intel.ipInfo else None,
            "country": domain_intel.ipInfo.country if domain_intel.ipInfo else None,
            "city": domain_intel.ipInfo.city if domain_intel.ipInfo else None,
            "region": domain_intel.geo.region if domain_intel.geo else (domain_intel.ipInfo.region if domain_intel.ipInfo else None),
            "latitude": domain_intel.geo.latitude if domain_intel.geo else (domain_intel.ipInfo.latitude if domain_intel.ipInfo else None),
            "longitude": domain_intel.geo.longitude if domain_intel.geo else (domain_intel.ipInfo.longitude if domain_intel.ipInfo else None),
            "isTor": domain_intel.ipInfo.isTor if domain_intel.ipInfo else False,
            "isProxy": domain_intel.ipInfo.isProxy if domain_intel.ipInfo else False,
            "isVPN": domain_intel.ipInfo.isVPN if domain_intel.ipInfo else False,
        },
    }
