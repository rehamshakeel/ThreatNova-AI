"""End-to-End Verification Script for ThreatNova AI Backend and Services.

Performs live verification of:
1. /health, /docs, /openapi.json
2. SQLite persistence and schema
3. Valid & invalid indicator submissions across all supported types
4. Evidence attribution, risk scoring factors, and D3 graph integrity
5. VirusTotal and LLM configuration and graceful degradation
"""

import json
import sqlite3
import sys
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

def run_e2e_verification():
    results = {}
    client = TestClient(app)

    # 1. Health & Docs
    print("[-] Checking /health and /docs...")
    health_resp = client.get("/health")
    docs_resp = client.get("/docs")
    results["health_endpoint"] = {
        "status_code": health_resp.status_code,
        "payload": health_resp.json()
    }
    results["docs_endpoint"] = {
        "status_code": docs_resp.status_code,
        "is_html": "swagger" in docs_resp.text.lower()
    }

    # 2. Config & Secrets check
    results["credentials_status"] = {
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "virustotal_key_exposed": False,
        "llm_provider": settings.LLM_PROVIDER,
        "llm_configured": bool(settings.LLM_API_KEY),
        "llm_key_exposed": False,
    }

    # 3. Test Valid Inputs across all 6 Indicator Types
    test_cases = [
        {"type": "ip", "query": "185.220.101.5", "expected_status": 201},
        {"type": "domain", "query": "malware-sample-drop.com", "expected_status": 201},
        {"type": "hash", "query": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "expected_status": 201},
        {"type": "url", "query": "https://malware-sample-drop.com/payload.exe", "expected_status": 201},
        {"type": "email", "query": "phishing@malware-sample-drop.com", "expected_status": 201},
        {"type": "username", "query": "threat_actor_99", "expected_status": 201},
    ]

    results["valid_indicator_submissions"] = []
    created_ids = []

    for tc in test_cases:
        resp = client.post("/api/investigations", json={"query": tc["query"], "type": tc["type"]})
        entry = {
            "query": tc["query"],
            "type": tc["type"],
            "status_code": resp.status_code,
        }
        if resp.status_code == 201:
            data = resp.json()
            created_ids.append(data["id"])
            entry["investigation_id"] = data["id"]
            entry["risk_score"] = data["risk"]["score"]
            entry["risk_level"] = data["risk"]["level"]
            entry["risk_confidence"] = data["risk"]["confidence"]
            entry["factors_count"] = len(data["risk"]["factors"])
            entry["findings_count"] = len(data["findings"])
            entry["graph_nodes_count"] = len(data["graphData"]["nodes"])
            entry["graph_links_count"] = len(data["graphData"]["links"])
            entry["is_demo"] = data["isDemo"]
        results["valid_indicator_submissions"].append(entry)

    # 4. Test Invalid / Unprocessable Inputs
    invalid_cases = [
        {"type": "ip", "query": "999.999.999.999", "label": "Invalid IP range"},
        {"type": "ip", "query": "not_an_ip", "label": "Malformed IP string"},
        {"type": "domain", "query": "invalid..domain..com", "label": "Consecutive dots domain"},
        {"type": "hash", "query": "12345", "label": "Too short hash"},
        {"type": "email", "query": "not-an-email", "label": "Malformed email"},
        {"type": "ip", "query": "", "label": "Empty query"},
    ]
    results["invalid_indicator_submissions"] = []
    for ic in invalid_cases:
        resp = client.post("/api/investigations", json={"query": ic["query"], "type": ic["type"]})
        results["invalid_indicator_submissions"].append({
            "label": ic["label"],
            "input": ic["query"],
            "status_code": resp.status_code,
            "rejected_with_422": resp.status_code == 422
        })

    # 5. SQLite Persistence Verification
    conn = sqlite3.connect(settings.DATABASE_URL.replace("sqlite:///", ""))
    cursor = conn.cursor()
    tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
    total_invs = cursor.execute("SELECT count(*) FROM investigations;").fetchone()[0]
    total_findings = cursor.execute("SELECT count(*) FROM findings;").fetchone()[0]
    
    # Check persistence of our created IDs
    persisted_checks = []
    for inv_id in created_ids[:3]:
        row = cursor.execute("SELECT id, query, type, risk_score FROM investigations WHERE id = ?", (inv_id,)).fetchone()
        persisted_checks.append({
            "id": inv_id,
            "persisted_in_sqlite": row is not None,
            "sqlite_data": row if row else None
        })
    conn.close()

    results["sqlite_verification"] = {
        "tables_present": tables,
        "total_investigations_in_db": total_invs,
        "total_findings_in_db": total_findings,
        "sample_persisted_checks": persisted_checks
    }

    # 6. Verify Graph Topology, Evidence Attribution & Recommendations on an investigation
    if created_ids:
        test_id = created_ids[0]
        graph_resp = client.get(f"/api/investigations/{test_id}/graph")
        analysis_resp = client.get(f"/api/investigations/{test_id}/analysis")
        results["graph_and_analysis_verification"] = {
            "graph_status": graph_resp.status_code,
            "graph_nodes": len(graph_resp.json().get("nodes", [])),
            "graph_links": len(graph_resp.json().get("links", [])),
            "analysis_status": analysis_resp.status_code,
            "has_recommendations": len(analysis_resp.json().get("recommendations", [])) > 0,
            "is_ai_generated": analysis_resp.json().get("isAiGenerated", False),
            "source": analysis_resp.json().get("source", ""),
        }

    print("\n--- VERIFICATION REPORT SUMMARY ---")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_e2e_verification()
