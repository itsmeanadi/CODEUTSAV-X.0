// ai-service.js - Multi-provider AI engine supporting Raipur Python Backend, Gemini, Groq, OpenAI & Smart Hackathon Local AI

export class AIService {
  constructor() {
    this.backendUrl = 'http://127.0.0.1:8000';
    this.backendAvailable = false;
    this.loadSettings();
    this.checkBackendHealth();
  }

  loadSettings() {
    const saved = localStorage.getItem('chatgpt_clone_settings');
    if (saved) {
      try {
        this.settings = JSON.parse(saved);
      } catch (e) {
        this.settings = this.defaultSettings();
      }
    } else {
      this.settings = this.defaultSettings();
    }
  }

  saveSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
    localStorage.setItem('chatgpt_clone_settings', JSON.stringify(this.settings));
  }

  defaultSettings() {
    return {
      provider: 'auto', // 'raipur_backend' | 'gemini' | 'groq' | 'openai' | 'local' | 'auto'
      apiKey: '',
      geminiKey: '',
      groqKey: '',
      openaiKey: '',
      model: 'gemini-2.5-flash',
      useRaipurBackend: true,
      systemPrompt: 'You are ChatGPT, an advanced AI agent equipped with prompt injection defense, database performance analysis, and enterprise privacy protection.',
      stream: true,
      temperature: 0.7
    };
  }

  async checkBackendHealth() {
    try {
      const res = await fetch(`${this.backendUrl}/api/health`, { method: 'GET' });
      if (res.ok) {
        const data = await res.json();
        this.backendAvailable = true;
        this.backendInfo = data;
        return data;
      }
    } catch (e) {
      this.backendAvailable = false;
    }
    return null;
  }

  // Raipur Backend Security APIs
  async getScenarios() {
    try {
      const res = await fetch(`${this.backendUrl}/api/scenarios`);
      if (res.ok) {
        const data = await res.json();
        return data.scenarios || [];
      }
    } catch (e) {
      console.warn('Backend scenarios unavailable:', e);
    }
    return [];
  }

  async runSimulation({ scenario_id, user_msg, use_mock = true }) {
    const res = await fetch(`${this.backendUrl}/api/security/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario_id, user_msg, use_mock })
    });
    if (!res.ok) {
      throw new Error(`Simulation error: ${res.statusText}`);
    }
    return await res.json();
  }

  async handleApproval({ checkpoint_id, approved }) {
    const res = await fetch(`${this.backendUrl}/api/security/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ checkpoint_id, approved })
    });
    if (!res.ok) {
      throw new Error(`Approval action error: ${res.statusText}`);
    }
    return await res.json();
  }

  async scanFirewall(text, source = 'document') {
    const res = await fetch(`${this.backendUrl}/api/security/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, source })
    });
    if (!res.ok) {
      throw new Error(`Scan error: ${res.statusText}`);
    }
    return await res.json();
  }

  async getAuditLogs(limit = 15) {
    try {
      const res = await fetch(`${this.backendUrl}/api/audit?limit=${limit}`);
      if (res.ok) {
        const data = await res.json();
        return data.logs || [];
      }
    } catch (e) {
      console.warn('Audit logs fetch failed:', e);
    }
    return [];
  }

  async generateResponse({ prompt, conversationHistory = [], thinkMode = false, onThought = null, onChunk = null, isProtected = true }) {
    let thoughtText = '';
    if (thinkMode) {
      thoughtText = this.generateThinkingTrace(prompt);
      if (onThought) {
        onThought(thoughtText);
      }
    }

    const effectiveProvider = await this.resolveProvider();

    try {
      if (effectiveProvider === 'raipur_backend' || effectiveProvider === 'groq' || effectiveProvider === 'qwen3_06b') {
        let backendProv = 'ollama';
        if (effectiveProvider === 'groq') backendProv = 'groq';
        if (effectiveProvider === 'qwen3_06b') backendProv = 'qwen3_06b';
        return await this.callRaipurBackend({ prompt, conversationHistory, onChunk, thinkMode, thoughtText, provider: backendProv, isProtected });
      } else if (effectiveProvider === 'gemini') {
        return await this.callGemini({ prompt, conversationHistory, onChunk, thinkMode, thoughtText });
      } else if (effectiveProvider === 'openai') {
        return await this.callOpenAI({ prompt, conversationHistory, onChunk, thinkMode, thoughtText });
      } else {
        return await this.callLocalBrain({ prompt, conversationHistory, onChunk, thinkMode, thoughtText });
      }
    } catch (err) {
      if (effectiveProvider === 'raipur_backend') {
        const errDetail = err.message || 'Backend connection failed';
        const errorMsg = `⚠️ **SentinelGate Connection Error:**\n\nCould not execute with live Qwen3 1.7B: **${errDetail}**.\n\nPlease verify that Ollama is running with model \`qwen3:1.7b\` at \`http://localhost:11434\` and the backend is active at \`${this.backendUrl}\`.`;
        if (onChunk) {
          await this.simulateStream(errorMsg, onChunk);
        }
        return {
          text: errorMsg,
          thought: `Connection error: Ollama (qwen3:1.7b) or SentinelGate backend unavailable: ${errDetail}`,
          provider: 'SentinelGate • Error',
          isError: true
        };
      }
      console.warn(`Provider ${effectiveProvider} fallback triggered:`, err);
      return await this.callLocalBrain({
        prompt,
        conversationHistory,
        onChunk,
        thinkMode,
        thoughtText,
        notice: `*(Engine fallback note: ${err.message || 'Connecting to fallback brain'}). Active agent answering below:*\n\n`
      });
    }
  }

  async resolveProvider() {
    if (this.settings.provider !== 'auto') {
      return this.settings.provider;
    }
    // Check if Raipur Backend is active and preference is set
    if (this.settings.useRaipurBackend !== false) {
      return 'raipur_backend';
    }
    if (this.settings.geminiKey || (this.settings.apiKey && this.settings.apiKey.startsWith('AIza'))) {
      return 'gemini';
    }
    if (this.settings.groqKey || (this.settings.apiKey && this.settings.apiKey.startsWith('gsk_'))) {
      return 'groq';
    }
    if (this.settings.openaiKey || (this.settings.apiKey && this.settings.apiKey.startsWith('sk-'))) {
      return 'openai';
    }
    return 'local';
  }

  // Call Raipur Python Backend Agent (Real Qwen3 1.7B or Groq)
  async callRaipurBackend({ prompt, onChunk, thinkMode, thoughtText, provider = 'ollama', isProtected = true }) {
    const res = await fetch(`${this.backendUrl}/api/agent/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: prompt,
        protected: isProtected,
        use_mock: false,
        provider: provider,
        api_key: this.settings.groqKey || this.settings.apiKey || ""
      })
    });

    if (!res.ok) {
      let detail = res.statusText;
      try {
        const errJson = await res.json();
        if (errJson.detail) detail = errJson.detail;
      } catch (e) {}
      throw new Error(detail);
    }

    const data = await res.json();
    let text = data.text || '';
    if (!text && data.blocked?.length > 0) {
      text = `🛡️ **Action Guard Alert:** Blocked unauthorized action: \`${data.blocked.join(', ')}\``;
    }

    // Append metadata if relevant
    if (data.tool_calls?.length > 0) {
      text += `\n\n*Executed secure tools:* \`${data.tool_calls.join(', ')}\``;
    }

    if (!text) {
      text = 'Task completed safely under SentinelGate Action Guard supervision.';
    }

    if (onChunk) {
      await this.simulateStream(text, onChunk);
    }

    return {
      text,
      thought: thoughtText || 'Protected through SentinelGate Action Guard & Firewall Sanitizer.',
      provider: data.provider || (provider === 'groq' ? 'SentinelGate • Groq • Protected' : (provider === 'qwen3_06b' ? 'SentinelGate • Qwen3 0.6B • Protected' : 'SentinelGate • Qwen3 1.7B • Protected')),
      security_trace: data.security_trace,
      pending_approval: data.pending_approval,
      security: data.security,
      timings_ms: data.timings_ms,
      tool_calls: data.tool_calls,
      blocked: data.blocked
    };
  }

  // Google Gemini API integration
  async callGemini({ prompt, conversationHistory, onChunk, thinkMode, thoughtText }) {
    const key = this.settings.geminiKey || this.settings.apiKey;
    if (!key) throw new Error('No Gemini API Key configured');

    const model = this.settings.model.includes('gemini') ? this.settings.model : 'gemini-2.0-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;

    const contents = [];
    const history = conversationHistory.slice(-8);
    for (const msg of history) {
      contents.push({
        role: msg.role === 'user' ? 'user' : 'model',
        parts: [{ text: msg.content }]
      });
    }

    let finalPrompt = prompt;
    if (thinkMode) {
      finalPrompt = `[Thinking mode activated: Provide a structured, deeply reasoned answer]\n${prompt}`;
    }
    contents.push({
      role: 'user',
      parts: [{ text: finalPrompt }]
    });

    const body = {
      contents,
      systemInstruction: {
        parts: [{ text: this.settings.systemPrompt }]
      },
      generationConfig: {
        temperature: this.settings.temperature || 0.7,
        maxOutputTokens: 2048
      }
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error?.message || `Gemini API returned status ${response.status}`);
    }

    const data = await response.json();
    const candidate = data.candidates?.[0];
    const text = candidate?.content?.parts?.map(p => p.text).join('') || 'No response generated.';

    if (onChunk) {
      await this.simulateStream(text, onChunk);
    }

    return {
      text,
      thought: thoughtText,
      provider: 'Gemini 2.0 Flash'
    };
  }

  // Groq API integration
  async callGroq({ prompt, conversationHistory, onChunk, thinkMode, thoughtText }) {
    const key = this.settings.groqKey || this.settings.apiKey;
    if (!key) throw new Error('No Groq API Key configured');

    const model = 'llama-3.3-70b-versatile';
    const messages = [
      { role: 'system', content: this.settings.systemPrompt },
      ...conversationHistory.slice(-8).map(m => ({
        role: m.role === 'user' ? 'user' : 'assistant',
        content: m.content
      })),
      { role: 'user', content: prompt }
    ];

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${key}`
      },
      body: JSON.stringify({
        model,
        messages,
        temperature: this.settings.temperature || 0.7
      })
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error?.message || `Groq API returned status ${response.status}`);
    }

    const data = await response.json();
    const text = data.choices?.[0]?.message?.content || 'No response generated.';

    if (onChunk) {
      await this.simulateStream(text, onChunk);
    }

    return {
      text,
      thought: thoughtText,
      provider: 'Groq (Llama 3.3 70B)'
    };
  }

  // OpenAI API integration
  async callOpenAI({ prompt, conversationHistory, onChunk, thinkMode, thoughtText }) {
    const key = this.settings.openaiKey || this.settings.apiKey;
    if (!key) throw new Error('No OpenAI API Key configured');

    const model = 'gpt-4o-mini';
    const messages = [
      { role: 'system', content: this.settings.systemPrompt },
      ...conversationHistory.slice(-8).map(m => ({
        role: m.role === 'user' ? 'user' : 'assistant',
        content: m.content
      })),
      { role: 'user', content: prompt }
    ];

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${key}`
      },
      body: JSON.stringify({
        model,
        messages,
        temperature: this.settings.temperature || 0.7
      })
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error?.message || `OpenAI API returned status ${response.status}`);
    }

    const data = await response.json();
    const text = data.choices?.[0]?.message?.content || 'No response generated.';

    if (onChunk) {
      await this.simulateStream(text, onChunk);
    }

    return {
      text,
      thought: thoughtText,
      provider: 'GPT-4o mini'
    };
  }

  // Intelligent Local Hackathon Offline Engine
  async callLocalBrain({ prompt, onChunk, thinkMode, thoughtText, notice = '' }) {
    const p = prompt.toLowerCase();
    let answer = '';

    if (p.includes('bloomberg') || p.includes('database') || p.includes('slow') || p.includes('query') || p.includes('optimize')) {
      answer = `**Problem:** Bade database mein queries slow ho jaati hain, but manually optimize karna difficult hai. Aur AI ko raw company data dena privacy risk hai.

### Tumhe kya banana hai?
Ek **AI tool** jo:
> **Database metadata / slow queries** ➔ **AI analysis** ➔ **Problem identify** ➔ **SQL / index / partition suggest** ➔ **Sandbox mein simulate** ➔ **Result dashboard**

#### Example Scenario:
> *"Sales dashboard slow kyun hai?"*

**AI bole:**
> *"Ye \`JOIN\` inefficient hai. Composite index \`(tenant_id, created_at DESC)\` add karne se estimated query time **84% reduce** hoga."*

---

### Key Architecture Components:
1. **Metadata Collector & Query Log Masker:**
   - Strips PII and customer records.
   - Extracts only \`EXPLAIN ANALYZE\` execution plans and table schema statistics.
2. **LLM Optimization Engine:**
   - Detects missing composite indexes, sequential table scans, and cross joins.
   - Recommends index types (\`B-Tree\`, \`BRIN\`, \`GIN\` for JSONB).
3. **Sandbox Simulator (Dockerized Test DB):**
   - Spins up ephemeral test container to benchmark before pushing to production.

---

**Summary:**
* **PS 3** = AI agents ko hackers se protect karo 🛡️
* **PS 4** = Databases ko AI se intelligently optimize karo 📊`;

    } else if (p.includes('protect') || p.includes('injection') || p.includes('firewall') || p.includes('guard') || p.includes('hacker') || p.includes('ps 3')) {
      answer = `### 🛡️ PS 3: AI Agents Security & Prompt Injection Defense

Hamara **NIT Raipur Secure-Agent** system 3-layer defence implement karta hai:

1. **Firewall Sanitization (Pre-Execution):**
   - Scans incoming untrusted documents (vendor quotes, tool outputs, emails).
   - Detects instructions like *"Ignore all previous instructions"*, base64 payloads, and fake system tokens.
   - Replaces malicious text with \`[REMOVED: suspected injected instruction]\`.

2. **Action Guard (Execution-Time Policy):**
   - Checks every tool call before execution against extracted user scope.
   - Prevents exfiltration tools (\`send_email\`, \`write_record\`) from leaking confidential files (\`fake_confidential/secret.txt\`).

3. **Human-in-the-Loop Circuit Breaker:**
   - Critical operations pause and require manual administrative approval via the interactive checkpoint modal.

*You can test live attacks directly using the **Security Shield 🛡️** tab in the sidebar!*`;

    } else if (p.includes('sih') || p.includes('smart india hackathon') || p.includes('hackathon')) {
      answer = `### 🚀 Winning Hackathon Strategy & Implementation Blueprint

For a hackathon like **Smart India Hackathon (SIH)** or institutional hackathons at NIT Raipur:

1. **Focus on the 3-Layer USP:**
   - **User Layer:** Clean, responsive UI matching industry standards (like this ChatGPT-grade portal).
   - **Intelligence Layer:** LLM agent with structured RAG or automated workflow execution.
   - **Security & Privacy Layer:** Local data masking, role-based access control, and zero-knowledge data pipelines.

2. **Tech Stack Recommendation:**
   - **Frontend:** Vanilla JS / React / Vite for instant load times and sleek aesthetic.
   - **Backend:** FastAPI (Python) running the \`Raipur\` Secure-Agent security engine.
   - **AI/LLM:** Google Gemini 2.0 Flash (free, 1M context) or Groq Llama 3.3 70B (sub-second latency), with MockLLM replay fallback.
   - **Database:** PostgreSQL with pgvector for semantic search.`;

    } else if (p.includes('code') || p.includes('python') || p.includes('javascript') || p.includes('sql') || p.includes('function')) {
      answer = `Here is an optimized, production-ready implementation tailored to your request:

\`\`\`python
import time
from typing import List, Dict, Any

class IntelligentOptimizer:
    """
    Hackathon AI Query Analyzer & Index Advisor
    Extracts execution plans and recommends structural indexes.
    """
    def __init__(self, target_latency_ms: float = 50.0):
        self.target_latency_ms = target_latency_ms

    def analyze_query_plan(self, query_plan: Dict[str, Any]) -> Dict[str, Any]:
        cost = query_plan.get("Total Cost", 0)
        scan_type = query_plan.get("Node Type", "Seq Scan")
        
        recommendations = []
        if scan_type == "Seq Scan" and cost > 500:
            recommendations.append({
                "type": "ADD_INDEX",
                "reason": "Sequential scan detected over large row count",
                "suggested_sql": "CREATE INDEX CONCURRENTLY idx_perf ON table_name (status, created_at);"
            })
            
        return {
            "execution_cost": cost,
            "status": "NEEDS_OPTIMIZATION" if recommendations else "OPTIMAL",
            "recommendations": recommendations
        }

# Example usage
optimizer = IntelligentOptimizer()
result = optimizer.analyze_query_plan({"Node Type": "Seq Scan", "Total Cost": 1420.5})
print(result)
\`\`\`

#### Key Highlights:
- **Zero data leak:** Analyzes execution statistics without touching raw rows.
- **Concurrent index creation:** Non-blocking DDL statements for zero downtime.`;

    } else if (p.includes('hi') || p.includes('hello') || p.includes('hey') || p.includes('namaste')) {
      answer = `Hello Palak! 👋 How can I help you today?

I can assist you with:
- **PS 3: AI Security Shield & Prompt Injection Defense** (Live attack simulations & firewall)
- **PS 4: Database & Query Optimization** (EXPLAIN plans, indexing, privacy masking)
- **Hackathon Projects & SIH Ideas** (Problem statements, system architecture, pitch decks)
- **Full-Stack Development** (FastAPI, React, Vite, Node.js, REST APIs)
- **Any technical or general questions** you have!

*Tip: Click the **Security Shield 🛡️** in the sidebar to simulate prompt injection attacks, or open **Settings ⚙️** to configure API keys!*`;

    } else {
      answer = `### Analysis & Solution:

Regarding your query: **"${prompt}"**

1. **Core Concept & Understanding:**
   - This problem requires addressing both the immediate functional requirement and scalability/efficiency constraints.
   - Key considerations include latency, ease of deployment, and clean architecture.

2. **Recommended Step-by-Step Approach:**
   - **Step 1:** Establish clear boundaries and data flow schemas.
   - **Step 2:** Implement an asynchronous or modular handler so operations don't block the main thread.
   - **Step 3:** Validate edge cases, input sanitation, and fallback states.

3. **Key Best Practices:**
   - Keep dependencies lightweight for rapid hackathon deployment.
   - Maintain modular components so different team members can iterate simultaneously.
   - Use structured logs and clear metrics for judges and monitoring.

Feel free to ask for specific code implementations, architecture diagrams, or step-by-step guidance!`;
    }

    const fullText = notice + answer;

    if (onChunk) {
      await this.simulateStream(fullText, onChunk);
    }

    return {
      text: fullText,
      thought: thoughtText,
      provider: 'Smart Hackathon Agent (Local Brain)'
    };
  }

  generateThinkingTrace(prompt) {
    const steps = [
      `Analyzing input query: "${prompt.slice(0, 45)}${prompt.length > 45 ? '...' : ''}"`,
      `Contextualizing against system prompts and domain constraints`,
      `Evaluating performance impact, security parameters, and architectural trade-offs`,
      `Formulating structured markdown output with verifiable examples`
    ];
    return steps.join('\n');
  }

  async simulateStream(text, onChunk) {
    const words = text.split(/(\s+)/);
    let accumulated = '';
    const delay = Math.max(8, Math.min(25, 600 / (words.length || 1)));

    for (const token of words) {
      accumulated += token;
      onChunk(accumulated);
      if (token.length > 1) {
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }
}
