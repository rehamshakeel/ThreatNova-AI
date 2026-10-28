"""Tests for investigation CRUD, D3 graph, and AI analysis endpoints."""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_create_and_fetch_investigation():
    # 1. Create investigation
    payload = {"query": "198.51.100.23", "type": "ip"}
    create_resp = client.post("/api/investigations", json=payload)
    assert create_resp.status_code == 201
    created_data = create_resp.json()

    inv_id = created_data["id"]
    assert inv_id.startswith("inv-")
    assert created_data["query"] == "198.51.100.23"
    assert created_data["type"] == "ip"
    assert created_data["status"] == "complete"
    assert created_data["risk"]["score"] > 0
    assert "factors" in created_data["risk"]
    assert len(created_data["findings"]) >= 1

    # 2. Get investigation by ID
    get_resp = client.get(f"/api/investigations/{inv_id}")
    assert get_resp.status_code == 200
    fetched_data = get_resp.json()
    assert fetched_data["id"] == inv_id

    # 3. Get investigation D3 graph
    graph_resp = client.get(f"/api/investigations/{inv_id}/graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "links" in graph_data
    assert len(graph_data["nodes"]) >= 1

    # 4. Get investigation AI analysis
    analysis_resp = client.get(f"/api/investigations/{inv_id}/analysis")
    assert analysis_resp.status_code == 200
    analysis_data = analysis_resp.json()
    assert "summary" in analysis_data
    assert "recommendations" in analysis_data
    assert len(analysis_data["recommendations"]) >= 1

    # 5. List investigations includes created one
    list_resp = client.get("/api/investigations?limit=10")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert any(item["id"] == inv_id for item in list_data)

    # 6. Delete investigation
    delete_resp = client.delete(f"/api/investigations/{inv_id}")
    assert delete_resp.status_code == 200

    # 7. Confirm 404 after deletion
    not_found_resp = client.get(f"/api/investigations/{inv_id}")
    assert not_found_resp.status_code == 404


def test_invalid_indicator_rejection():
    payload = {"query": "not_an_ip_or_domain_or_hash", "type": "ip"}
    resp = client.post("/api/investigations", json=payload)
    assert resp.status_code == 422


def test_quick_indicator_lookup():
    resp = client.get("/api/indicators/ip/8.8.8.8")
    assert resp.status_code == 200
    data = resp.json()
    assert data["indicator"] == "8.8.8.8"
    assert data["type"] == "ip"
    assert data["valid"] is True
    assert "reputation" in data
    assert "network" in data


def test_invalid_indicator_type():
    resp = client.get("/api/indicators/invalid_type/8.8.8.8")
    assert resp.status_code == 400

