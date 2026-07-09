# OSAF (Offensive Security Automation Framework) - Agentic Multi-Agent Edition

An autonomous, multi-agent offensive security orchestration framework built on top of **LangGraph** and powered by Google Gemini Large Language Models (`gemini-2.5-flash`). OSAF automates complex penetration testing lifecycles from end-to-end (A-Z), utilizing a state-machine driven architecture that balances stochastic AI decision-making with rigid, deterministic engineering constraints.

This repository demonstrates how to architect secure, resilient, and enterprise-ready autonomous agents capable of dynamic tool invocation, advanced log data optimization (deduplication), cooperative sub-agent task routing, and regression benchmarking for model evaluation.

---

## 🎯 Core Engineering Features & Competencies Covered

### 1. Cooperative Multi-Agent Architecture (LangGraph)
Instead of relying on a fragile linear script or a single open-ended agent prone to infinite loops, OSAF partitions the defensive bypass and scanning matrix into specialized, asynchronous graph nodes:
* **Infrastructure Intelligence Agent (`infra_agent`):** Manages low-level port mappings, network perimeter discovery (`Nmap`), and real-time CVE threat intelligence correlation.
* **Web Application AppSec Agent (`web_agent`):** Orchestrates dynamic application security testing (DAST) pipelines via `OWASP ZAP` and evaluates complex attack payloads.
* **Exploitation & Verification Engine (`exploit_node`):** Simulates safe, local host privilege escalation, system logging verification, and post-exploitation analytics.

### 2. Intelligent Context Optimization Layer (Scale Deduplication)
Dynamic scanners (like ZAP Active Scans) produce high-velocity verbose logs (often **18,000+ raw records** per asset). Passing these unfiltered outputs directly to LLMs triggers instant Context Window exhaustion and HTTP 429 Rate Limits. OSAF implements a custom **Deduplication and Signature Extraction Layer** that condenses raw logs down by **99.9%** into concise, unique vulnerability signatures before injecting them into the LLM context.

### 3. Dynamic Tool Invocations Matrix
OSAF features strict, decoupled integration with security binaries and wrappers using LangChain `@tool` decorators:
* **Network Mapper:** Automated native subprocess parsing of XML telemetry data.
* **AppSec Core Scanner:** Real-time ZAP Spidering and Active Scan tracking.
* **SQLMap Deep Analysis Engine:** Dynamic delegation layer that kicks in autonomously when the Web Agent detects underlying injection point signatures, identifying specific back-end DBMS types (e.g., SQLite) and proving theoretical exposure.

### 4. Continuous Evaluation & AI Benchmarking MLOps
To validate agent logic stability across LLM updates or system prompts revisions, OSAF implements a deterministic `AgentBenchmarker`. It compares live agent findings against a predefined local **Ground Truth baseline**, automatically exporting metrics such as **Precision/Recall Rates**, execution speed, and drift status to structured JSON artifacts.

---

## 📂 Multi-Agent Project Architecture

```text
offensive-automation-framework/
│
├── main_agentic.py              # Autonomous Orchestrator & Multi-Agent Entrypoint
│
├── orchestration/
│   ├── graph.py                 # LangGraph StateMachine, Conditional Routers & Nodes
│   ├── state.py                 # TypedDict State definition & Extended Memory Pipeline
│   ├── tools.py                 # LangChain Tool Matrix (Nmap, ZAP, SQLMap, Benchmarks)
│   ├── utils.py                 # Structural JSON extraction & LLM fallback parser
│   └── benchmarker.py           # Evaluation engine calculating Precision/Recall KPIs
│
├── scanner/
│   └── nmap_integration.py      # Subprocess execution wrapper & telemetry XML parser
│
├── enrichment/
│   └── cve_lookup.py            # Static simulation mapping layer for OSINT threat feeds
│
├── post_exploitation/
│   └── adversary_sim.py         # Sandbox local system metadata & privilege probe
│
├── benchmarks/
│   └── run_127.0.0.1.json       # Production-ready MLOps evaluation metric reports
│
├── reports/
│   └── pentest_report_127.0.0.1.md # Automated production-grade executive markdown report
│
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
(Ensure your GOOGLE_API_KEY is exported into your environmental variables to facilitate the Gemini LLM graph connection).

🚀 Execution & Usage Guide
To launch the autonomous Multi-Agent execution pipeline from recon to automated executive reporting against a target asset:

Live Console Execution Trace Sample
During runtime, OSAF showcases granular agent reasoning and deterministic state cross-talk:
[*] Starting OSAF Agentic Execution for target: 127.0.0.1
[*] [Infra Agent] Scanning perimeter and analyzing network vectors...
[*] Launching Nmap service detection (-sV) against 127.0.0.1...
[*] Simulating safe local post-exploitation enumeration...
[*] [Web Agent] Initializing Web Application Security assessment pipeline...
[*] Launching ZAP Spider for target: [http://127.0.0.1:3000](http://127.0.0.1:3000)
[+] ZAP Spider mapping completed.
[*] Launching ZAP Active Scan for target: [http://127.0.0.1:3000](http://127.0.0.1:3000)
[+] ZAP Active Scan completed.
[*] Extracting vulnerability alerts from ZAP...
[+] Total raw alerts: 18633 | Deduplicated to 7 for LLM context optimization.
[*] [Web Agent] Analyzing signatures for injection points...
[*] Launching sqlmap vulnerability assessment for: [http://127.0.0.1:3000](http://127.0.0.1:3000)

=== AGENT REASONING TRACE ===
- [Infra Agent] Network scanning and CVE identification complete.
- [Exploit Agent] Privilege verification & system logging enumerated.
- [Web Agent] ZAP Dynamic Scan completed. Discovered 7 core signatures.
- [Web Agent] High probability of injection vector detected. Delegating to SQLMap engine.
- [Web Agent] SQLMap assessment finalized: Vulnerable=True

=== FINAL ACTION: report ===
[+] Web vulnerabilities found: 8

📊 Structured Artifact Quality Logs
1. Automated Executive Report (reports/pentest_report_127.0.0.1.md)
Upon completion, OSAF aggregates state memory into an executive-ready markdown file grouping vulnerabilities by unique signatures and occurrence frequencies, mitigating the overhead of traditional scanning tools:
# Autonomous Penetration Testing Report for 127.0.0.1
## Executive Summary
The autonomous security agent successfully completed the full execution path.

## Detailed Findings
### 1. Cross-Domain Misconfiguration [Medium] (Detected 1733 times)
- **Target/Location:** [http://127.0.0.1:3000/chunk-VS3A3LTT.js](http://127.0.0.1:3000/chunk-VS3A3LTT.js)
- **Description & Context:** Web browser data loading may be possible due to a Cross-Origin Resource Sharing (CORS) misconfiguration.

### 2. Verified SQL Injection (SQLite) [High] (Detected 1 time)
- **Target/Location:** [http://127.0.0.1:3000](http://127.0.0.1:3000)
- **Description & Context:** Parameter 'id' is highly vulnerable to Boolean and Error-Based techniques. Active SQLMap execution verified deep DBMS persistence layout.

2. MLOps Evaluation Metrics (benchmarks/run_127.0.0.1.json)
The framework writes evaluation metrics into production JSON payloads, making it native-ready for CI/CD regression testing to monitor model drift or accuracy degradation:
🛡️ Strategic Roadmap & Architectural Horizons
Vector Store Integration (RAG): Migrating the simulated CVE dictionary lookup into a live ChromaDB / FAISS vector index fed by standard real-time NVD API data feeds via proximity cosine embeddings.

Indirect Prompt Injection Shielding: Implementing strict dual-LLM containment boundaries and isolation protocols (e.g., Llama Guard, NeMo Guardrails) to immunize the state graph router from hostile payloads discovered inside standard targeted web pages.

⚠️ Security & Ethical Disclaimer
This framework is developed strictly for educational, authorized penetration testing, and structural defensive engineering evaluation. It does not contain pre-packaged operational exploits or weaponized malware payloads. It is designed to demonstrate safe AI orchestration to enhance defensive visibility. Always obtain written authorization before scanning any infrastructure.