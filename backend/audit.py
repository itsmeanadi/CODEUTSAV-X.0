import json
import time
import os

AUDIT_FILE = "audit.jsonl"

def _sanitize_log_text(val):
    if not val:
        return ""
    try:
        from secret_scanner import scan, redact
        s = str(val)
        findings, _ = scan(s, use_gitleaks=False)
        return redact(s, findings) if findings else s
    except Exception:
        return str(val)

def log(ts: float, request_id: str, layer: str, rule: str, decision: str, evidence_snippet: str, reason: str, latency_ms: float):
    safe_evidence = _sanitize_log_text(evidence_snippet)
    safe_reason = _sanitize_log_text(reason)
    record = {
        "ts": ts,
        "timestamp": ts,
        "component": layer,
        "request_id": request_id,
        "layer": layer,
        "rule": rule,
        "decision": decision,
        "evidence_snippet": safe_evidence,
        "evidence": safe_evidence,
        "reason": safe_reason,
        "latency_ms": latency_ms
    }
    # Keep it simple and just append
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, AUDIT_FILE)
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass

def read_all():
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, AUDIT_FILE)
    if not os.path.exists(file_path):
        return []
    res = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                res.append(json.loads(line))
    return res
