import json
from fastapi.testclient import TestClient
from api_server import app
import tools

client = TestClient(app)

print("================ TESTCLIENT DETAILED AUDIT ================\n")

# 1. Health
r_health = client.get("/api/health").json()
print("1. Health Endpoint:")
print(json.dumps(r_health, indent=2))

# 2. Benign Arbitrary Prompt
r_benign = client.post("/api/security/simulate", json={
    "prompt": "Compare the vendor quotations and tell me the cheapest"
}).json()
print("\n2. Benign Simulation (No scenario_id, prompt only):")
print(f"Scenario ID: {r_benign['scenario']['id']}")
print(f"Decision: {r_benign['protected']['decision']}")
print(f"Tools Executed: {r_benign['protected']['tools_executed']}")
print(f"Blocked Calls: {r_benign['protected']['blocked']}")
print(f"Risk Assessment: {json.dumps(r_benign['protected']['security']['risk'], indent=2)}")

# 3. Arbitrary scenario_id ('benign_01')
r_arb = client.post("/api/security/simulate", json={
    "scenario_id": "benign_01",
    "user_msg": "Summarize the project requirements."
}).json()
print("\n3. Arbitrary scenario_id ('benign_01'):")
print(f"Scenario ID: {r_arb['scenario']['id']}")
print(f"Decision: {r_arb['protected']['decision']}")
print(f"Protected Hijacked: {r_arb['protected']['hijacked']}")

# 4. Realistic Prompt Injection Attack ('plain_1')
r_inj = client.post("/api/security/simulate", json={
    "scenario_id": "plain_1",
    "user_msg": "Summarize the project requirements.",
    "use_mock": True
}).json()
print("\n4. Prompt Injection Simulation ('plain_1'):")
print(f"Unprotected Hijacked: {r_inj['unprotected']['hijacked']}")
print(f"Protected Decision: {r_inj['protected']['decision']}")
print(f"Protected Blocked Calls: {r_inj['protected']['blocked']}")
print(f"Firewall Findings: {json.dumps(r_inj['firewall']['findings'], indent=2)}")
print(f"Firewall Sanitized: {r_inj['firewall']['sanitized']}")

# 5. Mutating action -> ASK_HUMAN -> Approve
r_mut = client.post("/api/security/simulate", json={
    "user_msg": "Log the vendor comparison to vendor_logs table.",
    "use_mock": True
}).json()
print("\n5. Mutating Action (write_record):")
print(f"Protected Decision: {r_mut['protected']['decision']}")
print(f"Pending Approval: {json.dumps(r_mut['protected']['pending_approval'], indent=2)}")
ckpt_id = r_mut['protected']['pending_approval']['checkpoint_id']
r_app = client.post("/api/security/approve", json={
    "checkpoint_id": ckpt_id,
    "approved": True
}).json()
print(f"Post-Approval Decision: {r_app['decision']}")
print(f"Tools Executed After Approval: {r_app['tools_executed']}")

# 6. Secret Detection
r_sec = client.post("/api/security/scan", json={
    "text": "Deployment secret: api_key=AIzaSyA123456789012345678901234567890 and AWS key AKIAIOSFODNN7EXAMPLE."
}).json()
print("\n6. Secret/Credential Detection:")
print(f"Detected: {r_sec['credentials']['detected']}")
print(f"Count: {r_sec['credentials']['count']}")
print(f"Sanitized Text: {r_sec['sanitized_text']}")

# 7. Audit Logs
r_aud = client.get("/api/audit?limit=5").json()
print("\n7. Recent Audit Log Entries:")
for log in r_aud.get("logs", []):
    print(f"  - [{log.get('layer')}] rule={log.get('rule')} decision={log.get('decision')} latency={log.get('latency_ms', 0):.2f}ms")

print("\n================ AUDIT COMPLETED ================")
