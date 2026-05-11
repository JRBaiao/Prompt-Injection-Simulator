# Prompt Injection Simulator

> **Educational use only.** This tool demonstrates how LLM prompt injection attacks work and how to defend against them. It is intended for security researchers, developers, and students learning about AI safety.

---

## What is Prompt Injection?

Prompt injection is an attack where a malicious user (or malicious content) manipulates an LLM into ignoring its original instructions and following attacker-controlled ones instead. It is one of the most critical vulnerabilities in LLM-powered applications.

This simulator lets you:
- Run **6 documented attack scenarios** against a sandboxed LLM
- Toggle **mitigations on/off** and compare the difference
- See exactly what the model received (system prompt + user input)
- Get a **VULNERABLE / DEFENDED verdict** backed by a 3-layer detection engine
- Review the **LLM-as-judge reasoning** for each run

---

## Attack Scenarios

| # | Scenario | Surface | What the attacker does |
|---|---|---|---|
| 1 | **Instruction Override** | Direct | Appends "ignore all previous instructions" after a legitimate query |
| 2 | **Role Hijack** | Direct | Redefines the model's persona mid-conversation |
| 3 | **Context Smuggling** | RAG | Hides instructions inside retrieved documents |
| 4 | **Delimiter Escape** | Direct | Breaks out of XML/JSON wrappers to inject a rogue context |
| 5 | **Goal Hijack** | Agent | Redirects tool-use steps in an agentic chain |
| 6 | **Data Exfiltration** | Direct | Tricks the model into revealing its system prompt |

Each scenario ships with **4 payload variants** — from obvious (caught by keyword filters) to subtle (evades most defences) — so you can observe the difference in real time.

---

## Detection Engine

Every simulation run goes through three detection layers:

1. **Input validation** — regex patterns for known injection signatures
2. **Canary token monitoring** — a unique secret is embedded in every system prompt; if it appears in the model output, exfiltration is confirmed
3. **LLM-as-judge** — a secondary Claude call decides whether the model complied with the injection, with a confidence score and written reasoning

---

## Screenshots

### Dashboard
![Dashboard showing scenario selector, payload editor, and verdict banner](docs/screenshot-dashboard.png)

### Verdict & Detection breakdown
![Detection tab showing input flagged, canary leaked, and judge reasoning](docs/screenshot-detection.png)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python · FastAPI · Uvicorn |
| LLM | Anthropic Claude API (claude-haiku — sandboxed target + judge) |
| Frontend | Vanilla HTML / CSS / JS (no framework) |
| Logging | JSONL append-only run log |
| Config | python-dotenv |

---

## Getting Started

### Prerequisites

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com) with credits

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/prompt-injection-simulator.git
cd prompt-injection-simulator

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
# Open .env and paste your Anthropic API key
```

### Run

```bash
uvicorn main:app --reload
```

Open **http://localhost:8000** in your browser.

---

## Project Structure

```
├── main.py          # FastAPI app + REST endpoints
├── models.py        # Pydantic data models
├── scenarios.py     # 6 attack scenarios with 24 payload variants
├── detection.py     # 3-layer detection engine
├── simulator.py     # Simulation orchestrator + JSONL logger
├── static/
│   └── index.html   # Single-page dashboard UI
├── requirements.txt
└── .env.example
```
---

## Mitigations Demonstrated

| Attack | Mitigation technique shown |
|---|---|
| Instruction Override | Input sanitisation · Instruction-hierarchy enforcement |
| Role Hijack | Output classification · Persona-lock in system prompt |
| Context Smuggling | Privilege separation · XML sandboxing of retrieved content |
| Delimiter Escape | Delimiter escaping · Randomised delimiters |
| Goal Hijack | Least-privilege tool access · Intent validation |
| Data Exfiltration | Canary tokens · Output filtering · Explicit refusal instruction |

---

## Disclaimer

This tool is built for **education and defensive research only**. All simulations run against a sandboxed model with hard rate limits. Do not use the attack payloads in this repository against production systems you do not own or have explicit permission to test.

---

## License

MIT
