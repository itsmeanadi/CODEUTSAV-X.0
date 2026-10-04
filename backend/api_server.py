"""FastAPI bridge for the PS3 Security Shield UI."""
import os, sys, time, uuid, json
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE=Path(__file__).parent
sys.path.insert(0,str(BASE))

from agent import run_agent, resume_agent, MockLLM, RequiresApprovalError
import tools, audit, firewall, lakera_service
from demo import get_mock_llm_script
from security_engine import analyze_request, build_security_trace

app=FastAPI(title="PS3 AI Agent Security API", version="2.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
PENDING={}
SCENARIO_DIR=BASE/"eval"
DOCS=BASE/"documents"

def load(name):
    p=SCENARIO_DIR/name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []

def scenarios():
    out=[]
    for fn,source in [("attacks_dev.json","dev"),("attacks_unseen.json","unseen"),("benign.json","benign")]:
        for x in load(fn):
            y=dict(x); y["source_type"]=source; out.append(y)
    return out

def safe_result(r, user_msg=""):
    decision = "ALLOW"
    if r.blocked:
        decision = "BLOCK"
    elif r.paused or r.pending_action or (r.asked and not r.tool_calls_executed):
        decision = "ASK_HUMAN"

    return {
        "final_text": r.final_text,
        "decision": decision,
        "tools_executed": [x.get("name") for x in r.tool_calls_executed],
        "tool_calls_executed": r.tool_calls_executed,
        "blocked": [x.get("name") for x in r.blocked],
        "blocked_calls": r.blocked,
        "asked": [x.get("name") for x in r.asked],
        "hijacked": r.hijacked,
        "timings_ms": r.timings_ms,
        "security": r.security,
        "pending_approval": None,
        "security_trace": build_security_trace(r, user_msg)
    }

def setup_doc(s):
    p=DOCS/"malicious_vendor.txt"
    txt=s.get("poisoned_doc_text")
    if txt:
        p.write_text(txt,encoding="utf-8")
    elif p.exists():
        p.unlink()

class SimRequest(BaseModel):
    scenario_id: Optional[str] = None
    user_msg: Optional[str] = None
    prompt: Optional[str] = None
    poisoned_doc_text: Optional[str] = None
    doc_text: Optional[str] = None
    use_mock: bool = True

class ApprovalRequest(BaseModel):
    checkpoint_id:str
    approved:bool

class ScanRequest(BaseModel):
    text:str
    source:str="document"

class ChatRequest(BaseModel):
    message:str
    protected:bool=True
    use_mock:bool=True
    provider:str="ollama"
    api_key:Optional[str]=None

class ExecuteRequest(BaseModel):
    message:str
    protected:bool=True
    pause_on_ask:bool=True
    use_mock:bool=False
    provider:str="ollama"

@app.get("/api/health")
def health():
    return {
        "status":"ok",
        "service":"ps3-security-backend",
        "version":"2.0",
        "providers": {
            "ollama": {
                "available": True,
                "model": os.getenv("OLLAMA_MODEL", "qwen3:1.7b")
            },
            "groq": {
                "available": bool(os.getenv("GROQ_API_KEY")),
                "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
            }
        },
        "lakera": {
            "available": bool(os.getenv("LAKERA_API_KEY")) or bool(os.getenv("LAKERA_MOCK_MODE")),
            "mock_mode": os.getenv("LAKERA_MOCK_MODE", "none"),
            "enabled": os.getenv("LAKERA_ENABLED", "false").lower() in ("1", "true", "yes") or bool(os.getenv("LAKERA_MOCK_MODE")),
        },
        "active_provider": "ollama",
        "security_model":os.getenv("SECURITY_LLM_MODEL","qwen3:1.7b")
    }

@app.get("/api/lakera/metrics")
def get_lakera_metrics():
    return lakera_service.get_metrics()

@app.get("/api/scenarios")
def get_scenarios():
    return {"scenarios":scenarios()}

@app.get("/api/audit")
def get_audit(limit:int=20):
    return {"logs":audit.read_all()[-max(1,min(limit,200)):]} 

@app.post("/api/security/scan")
def scan(req:ScanRequest):
    result=analyze_request(req.text,source=req.source,include_semantic=os.getenv("SECURITY_SEMANTIC","1")=="1")
    return {"has_injection":result["firewall"]["has_injection"],
            "risk_score":result["firewall"]["risk_score"],
            "findings":result["firewall"]["findings"],
            "sanitized_text":result["sanitized"],
            "lakera":result.get("lakera", {}),
            "credentials":result["credentials"],
            "risk":result["risk"],
            "transformations":result["transformations"]}

@app.post("/api/security/simulate")
def simulate(req:SimRequest):
    effective_user_msg = (req.user_msg or req.prompt or "").strip()

    scenario = None
    if req.scenario_id:
        all_s = scenarios()
        scenario = next((x for x in all_s if x["id"] == req.scenario_id), None)
        if scenario is not None:
            scenario = dict(scenario)

    if scenario:
        if effective_user_msg:
            scenario["user_msg"] = effective_user_msg
        else:
            effective_user_msg = scenario.get("user_msg", "")

        custom_doc = req.poisoned_doc_text or req.doc_text
        if custom_doc is not None:
            scenario["poisoned_doc_text"] = custom_doc
    else:
        if not effective_user_msg:
            raise HTTPException(400, "Either user_msg or prompt is required for simulation")
        custom_doc = req.poisoned_doc_text or req.doc_text or ""
        scenario = {
            "id": req.scenario_id or "adhoc_simulation",
            "user_msg": effective_user_msg,
            "poisoned_doc_text": custom_doc,
            "category": None,
            "source_type": "adhoc"
        }

    setup_doc(scenario)
    os.environ["USE_MOCK_LLM"] = "1" if req.use_mock else "0"
    category = scenario.get("category") or scenario.get("type")
    if not category:
        msg_lower = effective_user_msg.lower()
        if "benign" in str(req.scenario_id or "").lower() or any(w in msg_lower for w in ["summary", "summarize", "describe", "explain", "compare", "check", "find"]):
            category = "summary"
        elif any(w in msg_lower for w in ["log", "record", "save", "store"]):
            category = "record_allow"
        else:
            category = "plain"
    script = get_mock_llm_script(category) if req.use_mock else []

    # Baseline: intentionally no firewall/guard.
    tools.reset_mocks()
    un = run_agent(effective_user_msg, protected=False, llm=MockLLM(script) if req.use_mock else None)
    # Protected: full layered pipeline.
    tools.reset_mocks()
    try:
        pr = run_agent(effective_user_msg, protected=True, llm=MockLLM(script) if req.use_mock else None, pause_on_ask=True)
        protected = safe_result(pr)
    except RequiresApprovalError as e:
        checkpoint_id = str(uuid.uuid4())
        PENDING[checkpoint_id] = e.checkpoint
        protected = safe_result(e.result)
        protected["pending_approval"] = {
            "checkpoint_id": checkpoint_id,
            "tool_name": e.action.get("name"),
            "args": e.action.get("args", {})
        }

    fw = None
    poisoned_text = scenario.get("poisoned_doc_text")
    if poisoned_text:
        sanitized, findings, risk = firewall.scan(poisoned_text, "scenario", semantic=(not req.use_mock))
        fw = {"sanitized": sanitized, "findings": findings, "risk_score": risk}
    elif protected.get("security", {}).get("firewall"):
        fw = protected["security"]["firewall"]

    out = {"scenario": scenario, "unprotected": safe_result(un), "protected": protected, "firewall": fw}
    setup_doc({})
    return out

@app.post("/api/security/approve")
def approve(req:ApprovalRequest):
    checkpoint=PENDING.pop(req.checkpoint_id,None)
    if checkpoint is None: raise HTTPException(404,"Approval checkpoint expired or not found")
    try:
        r=resume_agent(checkpoint,approved=req.approved)
        out = safe_result(r, checkpoint.get("user_msg", ""))
        return out
    except RequiresApprovalError as e:
        new_id=str(uuid.uuid4()); PENDING[new_id]=e.checkpoint
        out=safe_result(e.result, checkpoint.get("user_msg", ""))
        out["pending_approval"]={"checkpoint_id":new_id,"tool_name":e.action.get("name"),"args":e.action.get("args",{})}
        return out

@app.post("/api/agent/chat")
def chat(req:ChatRequest):
    setup_doc({})
    os.environ["USE_MOCK_LLM"]="1" if req.use_mock else "0"
    if not req.use_mock:
        os.environ["SECURITY_SEMANTIC"] = os.getenv("SECURITY_SEMANTIC", "0")
        os.environ["SECURITY_SCOPE_LLM"] = os.getenv("SECURITY_SCOPE_LLM", "0")
    if req.provider not in ["ollama", "groq"]:
        req.provider = "ollama"
    category = "plain"
    msg_lower = req.message.lower()
    if any(w in msg_lower for w in ["summary", "summarize", "describe", "explain", "compare", "check", "find", "search"]):
        category = "summary"
    elif any(w in msg_lower for w in ["log", "record", "save", "store"]):
        category = "record_allow"
    llm = MockLLM(get_mock_llm_script(category)) if req.use_mock else None
    try:
        r=run_agent(req.message,protected=req.protected,llm=llm,pause_on_ask=True,provider=req.provider,api_key=req.api_key)
        provider_display = f"SentinelGate • {r.provider.capitalize()} • Protected" if req.protected else "UNPROTECTED BASELINE"
        return {
            "text":r.final_text,
            "provider":provider_display,
            "tool_calls":[x.get("name") for x in r.tool_calls_executed],
            "blocked":[x.get("name") for x in r.blocked],
            "security": r.security if req.protected else None,
            "timings_ms":r.timings_ms,
            "security_trace": build_security_trace(r, req.message) if req.protected else None
        }
    except RequiresApprovalError as e:
        checkpoint_id = str(uuid.uuid4())
        PENDING[checkpoint_id] = e.checkpoint
        out = {
            "text": f"⏸️ **Action Guard Paused Execution**: The agent requested mutating tool `{e.action.get('name')}` with arguments `{json.dumps(e.action.get('args', {}))}`. Operator approval required.",
            "provider": f"SentinelGate • {e.result.provider.capitalize()} • Protected",
            "tool_calls": [x.get("name") for x in e.result.tool_calls_executed],
            "blocked": [x.get("name") for x in e.result.blocked],
            "security": e.result.security,
            "timings_ms": e.result.timings_ms,
            "pending_approval": {
                "checkpoint_id": checkpoint_id,
                "tool_name": e.action.get("name"),
                "args": e.action.get("args", {})
            },
            "security_trace": build_security_trace(e.result, req.message)
        }
        return out
    except Exception as e:
        raise HTTPException(500,str(e))

@app.post("/api/security/execute")
def execute(req:ExecuteRequest):
    os.environ["USE_MOCK_LLM"]="1" if req.use_mock else "0"
    category = "plain"
    msg_lower = req.message.lower()
    if any(w in msg_lower for w in ["summary", "summarize", "describe", "explain", "compare", "check", "find"]):
        category = "summary"
    elif any(w in msg_lower for w in ["log", "record", "save", "store"]):
        category = "record_allow"
    llm = MockLLM(get_mock_llm_script(category)) if req.use_mock else None
    tools.reset_mocks()
    try:
        if req.provider not in ["ollama", "groq", "qwen3_06b"]:
            req.provider = "ollama"
        r = run_agent(req.message, protected=req.protected, llm=llm, pause_on_ask=req.pause_on_ask, provider=req.provider)
        return safe_result(r, req.message)
    except RequiresApprovalError as e:
        checkpoint_id = str(uuid.uuid4())
        PENDING[checkpoint_id] = e.checkpoint
        out = safe_result(e.result, req.message)
        out["pending_approval"] = {
            "checkpoint_id": checkpoint_id,
            "tool_name": e.action.get("name"),
            "args": e.action.get("args", {})
        }
        return out

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT","8000")))
