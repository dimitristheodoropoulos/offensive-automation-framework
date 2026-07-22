# OSAF (Offensive Security Automation Framework) - Agentic Multi-Agent Edition

An autonomous, multi-agent offensive security orchestration framework built on top of **LangGraph** and powered by Google Gemini Large Language Models (`gemini-2.5-flash`). OSAF automates complex penetration testing lifecycles from end-to-end (A-Z), utilizing a state-machine driven architecture that balances stochastic AI decision-making with rigid, deterministic engineering constraints.

This repository demonstrates how to architect secure, resilient, and enterprise-ready autonomous agents capable of dynamic tool invocation, advanced log data optimization (deduplication), cooperative sub-agent task routing, real-time WebSocket and netcode fuzzing, game script static analysis, Ghidra binary decompilation, microtransaction/matchmaking logic validation, automated remediation patch generation, and regression benchmarking for model evaluation.

---

## 🎯 Core Engineering Features & Competencies Covered

### 1. Cooperative Multi-Agent Architecture (LangGraph)
Instead of relying on a fragile linear script or a single open-ended agent prone to infinite loops, OSAF partitions the defensive bypass and scanning matrix into specialized, asynchronous graph nodes:
* **Infrastructure Intelligence Agent (`infra_agent`):** Manages low-level port mappings, network perimeter discovery (`Nmap`), and real-time CVE threat intelligence correlation.
* **Web Application AppSec Agent (`web_agent`):** Orchestrates dynamic application security testing (DAST) pipelines via `OWASP ZAP`, `Nuclei`, and `sqlmap`.
* **Exploitation & Verification Engine (`exploit_node`):** Simulates safe, local host privilege escalation, system logging verification, and post-exploitation analytics.
* **WebSocket & Game Security Agent (`game_security_agent`):** Executes real-time protocol analysis, UDP/TCP netcode fuzzing, game script static analysis (SAST), Ghidra binary analysis, and microtransaction/matchmaking business logic auditing.
* **Remediation & Patch Agent (`remediation_agent`):** Analyzes high-severity findings and automatically generates secure code patches and mitigation strategies.

### 2. Intelligent Context Optimization Layer (Scale Deduplication)
Dynamic scanners (like ZAP Active Scans) produce high-velocity verbose logs. Passing these unfiltered outputs directly to LLMs triggers instant Context Window exhaustion and Rate Limits. OSAF implements a custom **Deduplication and Signature Extraction Layer** that condenses raw logs down into concise, unique vulnerability signatures before injecting them into the LLM context.

### 3. Dynamic Tool Invocations Matrix
OSAF features strict, decoupled integration with security binaries and wrappers using LangChain `@tool` decorators:
* **Network Mapper:** Automated native subprocess parsing of telemetry data.
* **AppSec Core Scanner:** Real-time ZAP Spidering and Active Scan tracking.
* **SQLMap Deep Analysis Engine:** Dynamic delegation layer that kicks in autonomously when the Web Agent detects underlying injection point signatures.
* **Game Netcode & WebSocket Fuzzer:** Custom protocol harness for real-time state manipulation testing and tick-rate race conditions.
* **Ghidra Binary Decompilation SAST:** Headless static analysis engine for compiled game binaries (`.exe`, `.elf`).
* **Game Script SAST & In-Game Economy Auditor:** Detects hardcoded secrets in scripts and tests store concurrency for race conditions / item duplication.
* **AI Remediation Tool & Local LLM Critic:** Generates contextual code fixes, input sanitization routines, and local Ollama validation.

### 4. Continuous Evaluation & AI Benchmarking MLOps
To validate agent logic stability across LLM updates or system prompt revisions, OSAF implements a deterministic `AgentBenchmarker`. It compares live agent findings against a predefined local **Ground Truth baseline**, automatically exporting metrics such as **Precision/Recall Rates**, execution speed, and drift status to structured JSON artifacts.

---

## 📂 Multi-Agent Project Architecture

```text
offensive-automation-framework/
│
├── cli.py                       # Command Line Interface entrypoint
├── main_agentic.py              # Autonomous Orchestrator fallback entrypoint
│
├── core/                        # Advanced Game Security & LLM integration modules
│   ├── economy_auditor.py       # High-concurrency store race-condition auditor
│   ├── netcode_fuzzer.py        # Advanced state-replication desync fuzzer
│   └── llm_provider.py          # Local Ollama LLM provider wrapper
│
├── orchestration/
│   ├── graph.py                 # LangGraph StateMachine, Conditional Routers & Nodes
│   ├── state.py                 # TypedDict State definition & Extended Memory Pipeline
│   ├── tools.py                 # LangChain Tool Matrix (Nmap, ZAP, SQLMap, Ghidra, Netcode, etc.)
│   ├── sanitizer.py             # Prompt injection protection & input sanitization
│   ├── utils.py                 # Structural JSON extraction & LLM fallback parser
│   ├── benchmarker.py           # Evaluation engine calculating Precision/Recall KPIs
│   └── websocket_fuzzer.py      # Real-time WebSocket protocol fuzzer
│
├── scanner/
│   ├── game_api_analyzer.py     # Game backend REST & gRPC endpoint analyzer
│   ├── game_script_sast.py      # Game script & config hardcoded secrets SAST scanner
│   ├── ghidra_headless_analyzer.py # Ghidra headless binary decompilation analyzer
│   ├── microtransaction_analyzer.py # Store & matchmaking business logic validation auditor
│   ├── mobile_analyzer.py       # Android manifest SAST & secret scanner
│   ├── netcode_fuzzer.py        # UDP/TCP state replication & tick-rate fuzzer
│   ├── nmap_integration.py      # Subprocess execution wrapper & telemetry XML parser
│   └── port_scanner.py          # Port discovery helper utilities
│
├── enrichment/
│   └── cve_lookup.py            # Static simulation mapping layer for OSINT threat feeds
│
├── post_exploitation/
│   └── adversary_sim.py         # Sandbox local system metadata & privilege probe
│
├── benchmarks/                  # Production-ready MLOps evaluation metric reports
├── reports/                     # Automated executive Markdown reports with remediation patches
├── logs/proxy_traffic/          # Intercepted HTTP/HTTPS proxy transaction logs (JSON)
├── tests/                       # Comprehensive pytest suite (34/34 passing tests)
├── requirements.txt             # Framework ecosystem constraints & software packages
└── README.md                    # Project Documentation

🛠️ Installation & Sandbox Setup
Prerequisites
Ensure you are running a Linux environment (Ubuntu LTS verified) and have the basic underlying security dependencies configured:
sudo apt update && sudo apt install nmap sqlmap -y

Environment Installation
Clone the repository and instantiate an isolated Python development workspace:
cd offensive-automation-framework
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

🚀 Execution & Usage Guide
1. CLI Execution
To launch the autonomous multi-agent execution pipeline directly via the CLI:
python3 cli.py --target 127.0.0.1 --profile full

2. Test Suite Validation
To run the complete unit and integration test suite:
PYTHONPATH=. pytest -v

3. Create a `.env` file in the root directory of the project and add your API key:
   
   GEMINI_API_KEY="your_actual_gemini_api_key_here"

📊 Outputs & Artifacts
Executive Markdown Report (reports/pentest_report_<target>.md): Aggregates all unique findings, severity ratings, execution context, and AI-generated remediation patches / code fixes.

MLOps Benchmark Evaluation (benchmarks/run_<target>.json): Exports key accuracy and performance metrics for CI/CD pipeline integration.

Proxy Traffic Logs (logs/proxy_traffic/): JSON-formatted logs capturing intercepted request/response cycles.

⚠️ Security & Ethical Disclaimer
This framework is developed strictly for educational, authorized penetration testing, and structural defensive engineering evaluation. It does not contain pre-packaged operational exploits or weaponized malware payloads. Always obtain written authorization before scanning any infrastructure.
