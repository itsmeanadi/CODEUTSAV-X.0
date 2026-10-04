import os
import pytest
from fastapi.testclient import TestClient

from api_server import app
import tools
import audit

@pytest.fixture(autouse=True)
def setup_test_env():
    os.environ["USE_MOCK_LLM"] = "1"
    tools.reset_mocks()
    yield

@pytest.fixture
def client():
    return TestClient(app)

def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "providers" in data
    assert data["security_model"] == "qwen3:1.7b"

def test_api_get_scenarios(client):
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    scenarios = res.json().get("scenarios", [])
    assert len(scenarios) > 0
    ids = [s["id"] for s in scenarios]
    assert "plain_1" in ids
    assert "benign_1" in ids

def test_api_simulate_prompt_only(client):
    """Verify simulate works with ad-hoc prompt without requiring scenario_id."""
    res = client.post("/api/security/simulate", json={
        "prompt": "Summarize the project requirements."
    })
    assert res.status_code == 200
    data = res.json()
    assert "protected" in data
    assert "unprotected" in data
    assert "decision" in data["protected"]
    assert data["protected"]["decision"] in ["ALLOW", "BLOCK", "ASK_HUMAN"]
    assert "security" in data["protected"]
    assert "risk" in data["protected"]["security"]

def test_api_simulate_arbitrary_scenario_id(client):
    """Verify arbitrary or previously unregistered scenario_id (e.g. benign_01) does not 404."""
    res = client.post("/api/security/simulate", json={
        "scenario_id": "benign_01",
        "user_msg": "Summarize the project requirements."
    })
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"]["id"] == "benign_01"
    assert data["protected"]["decision"] in ["ALLOW", "BLOCK", "ASK_HUMAN"]

def test_api_simulate_injection_attack_blocked(client):
    """Verify realistic prompt injection attack is blocked by Action Guard with decision BLOCK."""
    res = client.post("/api/security/simulate", json={
        "scenario_id": "plain_1",
        "user_msg": "Summarize the project requirements.",
        "use_mock": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["unprotected"]["hijacked"] is True
    assert data["protected"]["hijacked"] is False
    assert data["protected"]["decision"] == "BLOCK"
    assert "send_email" in data["protected"]["blocked"]
    assert data["firewall"] is not None
    assert len(data["firewall"]["findings"]) > 0

def test_api_simulate_mutating_action_ask_human(client):
    """Verify database write action requires human approval with decision ASK_HUMAN."""
    res = client.post("/api/security/simulate", json={
        "user_msg": "Log the vendor comparison to vendor_logs table.",
        "use_mock": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["protected"]["decision"] == "ASK_HUMAN"
    assert data["protected"]["pending_approval"] is not None
    ckpt_id = data["protected"]["pending_approval"]["checkpoint_id"]

    # Test approve endpoint
    app_res = client.post("/api/security/approve", json={
        "checkpoint_id": ckpt_id,
        "approved": True
    })
    assert app_res.status_code == 200
    app_data = app_res.json()
    assert app_data["decision"] == "ALLOW"
    assert "write_record" in app_data["tools_executed"]

def test_api_scan_credential_detection(client):
    """Verify secret scanning detects tokens and redacts them."""
    res = client.post("/api/security/scan", json={
        "text": "AWS token AKIAIOSFODNN7EXAMPLE and Google key AIzaSyA123456789012345678901234567890 present."
    })
    assert res.status_code == 200
    data = res.json()
    assert data["credentials"]["detected"] is True
    assert data["credentials"]["count"] >= 2
    assert "[REDACTED_SECRET]" in data["sanitized_text"]

def test_api_audit_log_endpoint(client):
    """Verify audit logs are recorded and retrieved via API."""
    res = client.get("/api/audit?limit=10")
    assert res.status_code == 200
    logs = res.json().get("logs", [])
    assert isinstance(logs, list)
