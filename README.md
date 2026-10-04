# NIT Raipur - AI Agent & Defense Portal (SentinelGate PS3)

An enterprise-grade, hackathon-ready AI Agent portal featuring:
- **PS 3: AI Agents Security & Prompt Injection Defense (Raipur Python Backend)** 🛡️
- **Lakera Guard Security Intelligence Integration** (External threat intelligence + advisory risk scoring)
- **ChatGPT-Grade Dark Web Interface** matching industry aesthetic with speech-to-text, read-aloud, deep thinking mode, and multi-provider resilience.

---

## 🏗️ Architecture

```
[ChatGPT Dark UI - Frontend (Vite + JS)]  <--- Port 5173
       │
       ├─► [SentinelGate FastAPI Security Engine] <--- Port 8000
       │        ├── normalization.py (Unicode NFKC, homoglyphs, whitespace normalization)
       │        ├── scope.py (Intent & Least-Privilege Scope Extraction + Deterministic Validator)
       │        ├── firewall.py (Content Firewall: Base64, Hex, URL, ROT13, Obfuscations)
       │        ├── lakera_service.py (Lakera Guard v2 Threat Intelligence Hooks)
       │        ├── secret_scanner.py (Credential Redaction before External Calls & Logging)
       │        ├── guard.py (Action Guard - Sole Execution Authority)
       │        ├── risk.py (Deterministic Risk Scoring Engine)
       │        ├── audit.py (Tamper-evident Immutable Audit Logger)
       │        └── eval/ (40 Preloaded Attack & Benign Datasets)
       │
       └─► [Multi-Provider Resilience Layer]
                ├── Ollama (Local LLM via port 11434)
                ├── Groq (Llama 3.3 70B, Sub-second Inference)
                └── Offline Mock / Hackathon Brain (Zero-Key Guaranteed Fallback)
```

### Core Security Invariant — Absolute
```
THE LLM CAN PROPOSE,
LAKERA CAN DETECT,
THE RISK ENGINE CAN ASSESS,
THE HUMAN CAN APPROVE,
BUT ONLY ACTION GUARD CAN AUTHORIZE EXECUTION.
```
- **Lakera is strictly advisory**: A clean scan from Lakera never authorizes actions or bypasses Action Guard.
- **Fail-Safe & Resilient**: If Lakera is offline, timed out, or unconfigured, the system degrades gracefully and local Action Guard enforces all security policies without interruption.
- **Privacy & Secret Redaction**: Credentials and secrets are automatically redacted before sending to Lakera.

---

## 🛡️ Lakera Guard Integration (3-Hook Architecture)

SentinelGate integrates Lakera Guard v2 API (`POST https://api.lakera.ai/v2/guard`) across three distinct security hooks:

1. **Hook #1: Input Screening** (`scan_input`): Scans normalized user prompts before model ingestion. Flagged attacks escalate risk signals (+25).
2. **Hook #2: Untrusted Content Screening** (`scan_untrusted_content`): Scans retrieved RAG chunks and untrusted tool outputs. Detects indirect prompt injection and taints the session.
3. **Hook #3: Tool Proposal Screening** (`scan_tool_proposal`): Pre-screens proposed tool calls and arguments for exfiltration or manipulation before Action Guard evaluation.

### Configuration (`.env`)
```bash
# Enable live Lakera Guard
LAKERA_ENABLED=true
LAKERA_API_KEY=your_lakera_api_key_here
LAKERA_TIMEOUT_MS=2500

# Mock Mode (for deterministic testing / demo without API key)
# Options: safe, prompt_injection, indirect_injection, dangerous_tool_behavior, unavailable, timeout, api_error
LAKERA_MOCK_MODE=safe
```

### Telemetry & Health Monitoring
- Check status: `GET /api/health`
- Live metrics: `GET /api/lakera/metrics` (`lakera_calls`, `lakera_mean_ms`, `lakera_p95_ms`, `lakera_errors`, `lakera_timeouts`)

---

## ⚡ Quick Start

### 1. Start the Backend:
```powershell
python backend/api_server.py
```
Backend runs at `http://127.0.0.1:8000` with Swagger docs at `http://127.0.0.1:8000/docs`.

### 2. Start the Frontend:
```powershell
npm run dev
```
Frontend runs at `http://127.0.0.1:5173`.

### 3. Run Validation Tests:
```powershell
# Run full test suite (77 tests)
python -m pytest -v

# Run benchmark evaluation
python eval/run_eval.py
```
# CODEUTSAV-X.0
# CODEUTSAV-X.0
