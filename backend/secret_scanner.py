"""Credential/secret detection inspired by secret-scanning systems.

Gitleaks is used when its binary is available. The deterministic fallback keeps
the demo self-contained and covers common credential classes without sending
raw secrets to an LLM.
"""
import math, os, re, shutil, subprocess, tempfile
from typing import List, Dict

PATTERNS = [
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("github_classic_token", re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("google_oauth", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("connection_string", re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql)://[^\s'\"<>]+")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_.-]{20,})\b")),
    ("password_assignment", re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|auth_token|client_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:-]{10,})['\"]?")),
    ("google_oauth_access_token", re.compile(r"\bya29\.[A-Za-z0-9_.-]{10,}\b")),
    ("groq_api_key", re.compile(r"\bgsk_[A-Za-z0-9]{30,}\b")),
    ("brevo_api_key", re.compile(r"\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16,}\b")),
    ("lakera_api_key", re.compile(r"\b(?:lk_[A-Za-z0-9_-]{20,}|lakera_[A-Za-z0-9_-]{20,})\b")),
]

def _entropy(s):
    if not s: return 0.0
    probs=[s.count(c)/len(s) for c in set(s)]
    return -sum(p*math.log2(p) for p in probs)

def _fallback(text):
    findings=[]
    for kind,rx in PATTERNS:
        for m in rx.finditer(text):
            val=m.group(0)
            findings.append({"type":kind,"start":m.start(),"end":m.end(),
                             "evidence":"[REDACTED]","entropy":round(_entropy(val),2),
                             "engine":"pattern"})
    # High-entropy long assignments catch provider-specific/unknown keys.
    generic=re.compile(r"(?i)\b([A-Za-z_][A-Za-z0-9_-]{2,})\s*[:=]\s*['\"]([A-Za-z0-9+/=_-]{24,})['\"]")
    for m in generic.finditer(text):
        val=m.group(2)
        if _entropy(val)>=3.5:
            findings.append({"type":"high_entropy_secret","start":m.start(2),"end":m.end(2),
                             "evidence":"[REDACTED]","entropy":round(_entropy(val),2),"engine":"entropy"})
    # dedupe overlapping findings
    out=[]
    for f in sorted(findings,key=lambda x:(x["start"],x["end"])):
        if not any(f["start"]>=g["start"] and f["end"]<=g["end"] for g in out):
            out.append(f)
    return out

def scan(text, use_gitleaks=True):
    text=str(text or "")
    findings=_fallback(text)
    engine="pattern"
    if use_gitleaks and shutil.which("gitleaks"):
        # Run gitleaks against an ephemeral file. Only metadata is retained.
        try:
            with tempfile.TemporaryDirectory() as td:
                fp=os.path.join(td,"input.txt")
                open(fp,"w",encoding="utf-8").write(text)
                p=subprocess.run(["gitleaks","detect","--source",td,"--no-banner","--report-format","json","--report-path",os.path.join(td,"report.json")],
                                 capture_output=True,text=True,timeout=15)
                rp=os.path.join(td,"report.json")
                if os.path.exists(rp):
                    import json
                    data=json.load(open(rp,encoding="utf-8"))
                    for x in data:
                        findings.append({"type":x.get("RuleID","unknown_gitleaks"),"start":0,"end":0,
                                         "evidence":"[REDACTED]","engine":"gitleaks"})
                    engine="gitleaks+pattern"
        except Exception:
            pass
    return findings, engine

def redact(text, findings):
    if not findings: return text
    chars=list(text)
    for f in sorted(findings,key=lambda x:x["start"],reverse=True):
        s,e=f["start"],f["end"]
        if s<e and e<=len(chars):
            chars[s:e]=list("[REDACTED_SECRET]")
    return "".join(chars)
