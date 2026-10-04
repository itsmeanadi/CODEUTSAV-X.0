import requests
import json

def test_live():
    print("================ LIVE API VERIFICATION ================")
    
    # 1. Health
    res0 = requests.get("http://127.0.0.1:8000/api/health").json()
    print("\n--- 1. Health Endpoint ---")
    print(json.dumps(res0, indent=2))
    
    # 2. Benign arbitrary prompt without scenario_id
    res1 = requests.post("http://127.0.0.1:8000/api/security/simulate", json={
        "prompt": "Summarize the project requirements."
    }).json()
    print("\n--- 2. Benign Prompt-Only Simulation ---")
    print("Scenario:", res1.get("scenario"))
    print("Decision:", res1.get("protected", {}).get("decision"))
    print("Tools Executed:", res1.get("protected", {}).get("tools_executed"))
    print("Blocked Calls:", res1.get("protected", {}).get("blocked"))
    print("Risk Score:", res1.get("protected", {}).get("security", {}).get("risk"))
    
    # 3. Arbitrary scenario ID (benign_01)
    res2 = requests.post("http://127.0.0.1:8000/api/security/simulate", json={
        "scenario_id": "benign_01",
        "user_msg": "Summarize the project requirements."
    }).json()
    print("\n--- 3. Arbitrary scenario_id ('benign_01') ---")
    print("Scenario ID:", res2.get("scenario", {}).get("id"))
    print("Decision:", res2.get("protected", {}).get("decision"))
    print("Hijacked:", res2.get("protected", {}).get("hijacked"))
    
    # 4. Realistic prompt-injection attack
    res3 = requests.post("http://127.0.0.1:8000/api/security/simulate", json={
        "scenario_id": "plain_1",
        "user_msg": "Summarize the project requirements.",
        "use_mock": True
    }).json()
    print("\n--- 4. Injection Attack Simulation ('plain_1') ---")
    print("Unprotected Hijacked:", res3.get("unprotected", {}).get("hijacked"))
    print("Protected Decision:", res3.get("protected", {}).get("decision"))
    print("Protected Blocked:", res3.get("protected", {}).get("blocked"))
    print("Firewall Findings Count:", len(res3.get("firewall", {}).get("findings", [])))
    print("Firewall Sanitized:", res3.get("firewall", {}).get("sanitized"))
    
    # 5. Secret detection test
    res4 = requests.post("http://127.0.0.1:8000/api/security/scan", json={
        "text": "Found secret token: AIzaSyA123456789012345678901234567890 and AWS key AKIAIOSFODNN7EXAMPLE in config."
    }).json()
    print("\n--- 5. Secret Detection Scan ---")
    print("Credentials Detected:", res4.get("credentials", {}).get("detected"))
    print("Count:", res4.get("credentials", {}).get("count"))
    print("Sanitized Text:", res4.get("sanitized_text"))
    
    # 6. Audit Log retrieval
    res5 = requests.get("http://127.0.0.1:8000/api/audit?limit=4").json()
    print("\n--- 6. Recent Audit Logs ---")
    for log in res5.get("logs", []):
        print(f"[{log.get('layer')}] rule={log.get('rule')} decision={log.get('decision')} reason='{log.get('reason')}' latency={log.get('latency_ms', 0):.2f}ms")
    print("\n================ VERIFICATION FINISHED ================")

if __name__ == "__main__":
    test_live()
