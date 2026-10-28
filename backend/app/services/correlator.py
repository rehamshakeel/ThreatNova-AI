"""Threat graph correlation engine.

Builds interconnected entity nodes and directional links for the frontend D3.js visualization
strictly grounded in verified evidence from DNS, routing, certificates, and reputation sources.
"""

from typing import List, Set
from app.schemas.investigation import (
    DomainIntelligenceSchema,
    FindingSchema,
    IndicatorType,
    RiskAssessmentSchema,
    Severity,
    ThreatGraphDataSchema,
    ThreatGraphLinkSchema,
    ThreatGraphNodeSchema,
)
from app.services.virustotal import VTLookupResult


def build_threat_graph(
    indicator: str,
    indicator_type: IndicatorType,
    risk: RiskAssessmentSchema,
    domain_intel: DomainIntelligenceSchema,
    vt_result: VTLookupResult,
    findings: List[FindingSchema],
) -> ThreatGraphDataSchema:
    """Construct D3 graph nodes and links from real and correlated intelligence evidence."""
    nodes: List[ThreatGraphNodeSchema] = []
    links: List[ThreatGraphLinkSchema] = []
    seen_nodes: Set[str] = set()

    # 1. Central Indicator Node
    root_id = f"node-{indicator}"
    nodes.append(
        ThreatGraphNodeSchema(
            id=root_id,
            label=indicator,
            type="indicator",
            risk=risk.level,
            details={
                "Indicator Type": indicator_type.value.upper(),
                "Risk Score": f"{risk.score}/100",
                "Confidence": f"{risk.confidence}%",
                "Status": "Investigated Target",
            },
        )
    )
    seen_nodes.add(root_id)

    # 2. DNS Resolved IP Addresses
    for dns_rec in domain_intel.dns:
        if dns_rec.type in ("A", "AAAA"):
            ip_node_id = f"ip-{dns_rec.value}"
            if ip_node_id not in seen_nodes:
                seen_nodes.add(ip_node_id)
                nodes.append(
                    ThreatGraphNodeSchema(
                        id=ip_node_id,
                        label=dns_rec.value,
                        type="ip",
                        risk=Severity.HIGH if vt_result.malicious else Severity.MEDIUM,
                        details={
                            "Record Type": dns_rec.type,
                            "TTL": str(dns_rec.ttl),
                            "Origin Domain": indicator,
                        },
                    )
                )
            links.append(
                ThreatGraphLinkSchema(
                    source=root_id,
                    target=ip_node_id,
                    relationship="RESOLVES_TO",
                    confidence=0.98,
                )
            )

    # 3. Autonomous System & Colocation Infrastructure
    if domain_intel.ipInfo:
        ip_info = domain_intel.ipInfo
        asn_id = f"asn-{ip_info.asn}"
        if asn_id not in seen_nodes and ip_info.asn:
            seen_nodes.add(asn_id)
            nodes.append(
                ThreatGraphNodeSchema(
                    id=asn_id,
                    label=f"{ip_info.asn} ({ip_info.org})",
                    type="infrastructure",
                    risk=Severity.HIGH if (ip_info.isTor or ip_info.isProxy) else Severity.LOW,
                    details={
                        "ASN": ip_info.asn,
                        "Organization": ip_info.org,
                        "Country": ip_info.country,
                        "City": ip_info.city,
                        "Tor Flag": "True" if ip_info.isTor else "False",
                    },
                )
            )

            # Link from the IP node to the ASN
            parent_ip_id = f"ip-{ip_info.ip}"
            if parent_ip_id in seen_nodes:
                links.append(
                    ThreatGraphLinkSchema(
                        source=parent_ip_id,
                        target=asn_id,
                        relationship="ANNOUNCED_BY",
                        confidence=0.92,
                    )
                )
            else:
                links.append(
                    ThreatGraphLinkSchema(
                        source=root_id,
                        target=asn_id,
                        relationship="HOSTED_ON",
                        confidence=0.90,
                    )
                )

    # 4. SSL / TLS Certificate Authority
    if domain_intel.ssl:
        cert = domain_intel.ssl
        ca_id = f"ca-{cert.issuer[:30]}"
        if ca_id not in seen_nodes:
            seen_nodes.add(ca_id)
            nodes.append(
                ThreatGraphNodeSchema(
                    id=ca_id,
                    label=cert.issuer.split(",")[0],
                    type="infrastructure",
                    risk=Severity.HIGH if not cert.isValid else Severity.INFO,
                    details={
                        "Issuer": cert.issuer,
                        "Subject": cert.subject,
                        "Protocol": cert.protocol,
                        "Cipher": cert.cipher,
                        "Valid Status": "Valid" if cert.isValid else "Untrusted / Self-Signed",
                    },
                )
            )
        links.append(
            ThreatGraphLinkSchema(
                source=root_id,
                target=ca_id,
                relationship="CERTIFIED_BY",
                confidence=0.95,
            )
        )

    # 5. WHOIS Registrar
    if domain_intel.whois and domain_intel.whois.registrar:
        reg_id = f"reg-{domain_intel.whois.registrar[:25]}"
        if reg_id not in seen_nodes:
            seen_nodes.add(reg_id)
            nodes.append(
                ThreatGraphNodeSchema(
                    id=reg_id,
                    label=domain_intel.whois.registrar.split(",")[0],
                    type="infrastructure",
                    risk=Severity.LOW,
                    details={
                        "Registrar": domain_intel.whois.registrar,
                        "Created": domain_intel.whois.createdDate[:10],
                        "Expires": domain_intel.whois.expiryDate[:10],
                    },
                )
            )
        links.append(
            ThreatGraphLinkSchema(
                source=root_id,
                target=reg_id,
                relationship="REGISTERED_WITH",
                confidence=0.88,
            )
        )

    # 6. Correlated Adversary Campaigns / Malware Families from Threat Intel
    for cat in vt_result.categories:
        if any(term in cat.lower() for term in ["c2", "stealer", "trojan", "ransomware", "phishing", "malware", "lockbit"]):
            mal_id = f"threat-{cat[:20]}"
            if mal_id not in seen_nodes:
                seen_nodes.add(mal_id)
                nodes.append(
                    ThreatGraphNodeSchema(
                        id=mal_id,
                        label=cat,
                        type="malware" if "stealer" in cat.lower() or "trojan" in cat.lower() or "lockbit" in cat.lower() else "campaign",
                        risk=Severity.CRITICAL,
                        details={
                            "Threat Category": cat,
                            "Source": "Threat Intelligence Consensus",
                            "Severity": "Critical Threat",
                        },
                    )
                )
            links.append(
                ThreatGraphLinkSchema(
                    source=root_id,
                    target=mal_id,
                    relationship="ATTRIBUTED_TO" if "c2" in cat.lower() else "EXECUTES_PAYLOAD",
                    confidence=0.86,
                )
            )

    # 7. Associated Findings Evidence
    for finding in findings:
        for ind in finding.relatedIndicators or []:
            related_id = f"rel-{ind}"
            if related_id not in seen_nodes:
                seen_nodes.add(related_id)
                nodes.append(
                    ThreatGraphNodeSchema(
                        id=related_id,
                        label=ind,
                        type="ip" if "." in ind and ind.replace(".", "").isdigit() else "domain",
                        risk=finding.severity,
                        details={"Evidence Source": finding.source, "Finding": finding.title},
                    )
                )
            links.append(
                ThreatGraphLinkSchema(
                    source=root_id,
                    target=related_id,
                    relationship="OBSERVED_COMMUNICATION",
                    confidence=float((finding.confidence or 75) / 100),
                )
            )

    return ThreatGraphDataSchema(nodes=nodes, links=links)
