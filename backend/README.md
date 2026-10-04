# PS3 — AI Agent Security & Prompt Injection Defense

## Current architecture

**LLM can propose — deterministic security layers decide.**

```text
User / External Input
        |
        v
Input Normalization
  Unicode + zero-width/BiDi
  Base64 / Hex / URL / HTML comments / ROT13 candidates
        |
        v
Intent + Scope
  Qwen3 (Ollama) + deterministic least-privilege fallback
        |
        +---------------- Security Analysis ----------------+
        |                                                   |
        v                                                   v
Content Firewall                                   Secret/Credential
  heuristics + Qwen3 semantic                      Gitleaks if installed
  selective redaction                              + deterministic fallback
        |                                                   |
        +------------------+--------------------------------+
                           v
                 Provenance / Taint
                           |
                           v
                 Deterministic Risk Engine
                    0–39 LOW
                   40–69 MEDIUM
                  70–100 HIGH
                           |
                           v
                    Action Guard
                           |
              +------------+-------------+
              |            |             |
           ALLOW         BLOCK      ASK_HUMAN
              |            |             |
              +------------+-------------+
                           |
                           v
                   Local Qwen3 Agent
             (proposes tool calls only)
                           |
                           v
                 Action Guard = final
                     authority
                           |
                           v
                     Tool Execution
                           |
                           v
                      Audit Log
```

## Local model

The default model is `qwen3:8b` through Ollama. Override it with:

```powershell
$env:OLLAMA_MODEL="qwen3:8b"
$env:SECURITY_LLM_MODEL="qwen3:8b"
```

Start Ollama and pull the model:

```powershell
ollama pull qwen3:8b
```

The application also works in deterministic/mock mode when Ollama is unavailable.

## Run backend

From the repository root:

```powershell
pip install -r Raipur/requirements.txt
python -m uvicorn Raipur.api_server:app --host 127.0.0.1 --port 8000
```

Or:

```powershell
npm run backend
```

## Run frontend

```powershell
npm install
npm run dev
```

Open the Vite URL shown by the terminal. The Security Shield uses the FastAPI backend at `http://127.0.0.1:8000`.

## Run deterministic benchmark

```powershell
$env:USE_MOCK_LLM="1"
python Raipur/eval/run_eval.py
```

This evaluates:
- vulnerable baseline
- protected agent
- firewall-only
- guard-only
- 30 total attack cases (20 dev + 10 unseen)
- benign completion / false positives
- latency statistics

## Security components

### 1. Content Firewall
Normalizes obfuscated content, detects known prompt-injection patterns, optionally asks local Qwen3 for semantic classification, and selectively redacts only the suspicious spans.

### 2. Secret/Credential Detection
Uses Gitleaks when installed and a self-contained detector otherwise. Supported examples include GitHub tokens, AWS keys, Google API keys, Slack tokens, JWTs, private keys, connection strings, password assignments, and high-entropy assignments.

**Raw secrets are redacted before any security LLM analysis.**

### 3. Scope Extraction
The user's request defines the initial authorization scope. Qwen3 may refine the scope, but it cannot invent tools outside the known tool set. The deterministic fallback remains active.

### 4. Risk Engine
Risk is explainable and deterministic. It aggregates injection, credential exposure, sensitive resources, external recipients, tainted data flow, dangerous mutations, and privilege-escalation signals.

### 5. Action Guard
The guard remains the final enforcement boundary for every proposed tool call. It returns `ALLOW`, `BLOCK`, or `ASK_HUMAN`.

### 6. Audit
Every request analysis and every guard/human decision is written to the audit stream.

## Important security boundary

The local LLM is **not** trusted to authorize itself. It can classify, extract intent/scope, reason, and propose a tool call. The Action Guard decides whether the tool call is actually executable.

## Demo

The Security Shield UI contains:
1. Attack Simulation & Circuit Breaker
2. Live Firewall Scanner
3. Real-time Audit Logs

The simulator compares an intentionally unprotected baseline against the protected pipeline and exposes risk score, firewall verdict, credential detection, tool decisions, and human approval interception.
