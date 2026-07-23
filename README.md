# OSAF (Offensive Security Automation Framework) — Agentic Multi-Agent Edition

An autonomous, multi-agent offensive security orchestration framework built on **LangGraph** and powered by Google Gemini (`gemini-2.5-flash`). OSAF automates a full penetration-testing lifecycle — recon, exploitation simulation, web AppSec testing, real-time game/netcode security auditing, remediation generation, and reporting — as a **state-machine-driven agent graph** rather than a linear script or an unconstrained single-agent loop.

---

## 🎯 Architecture Overview

### Multi-Agent Graph (LangGraph)

The core pipeline (`orchestration/graph.py`) compiles a `StateGraph` over a typed `PentestState` (`orchestration/state.py`) with 7 nodes, connected by a conditional router (`multi_agent_router`) that reads a `next_action` field the agents themselves set:

```
infra_agent ─┬─(exploit_recommended)──> exploit_node ──> web_agent
             └─(no exploit)────────────────────────────> web_agent
                                                              │
                                                        critic_agent
                                                         ├─(0 findings, <2 iters)──> retry web_agent
                                                         └─(validated)──> game_security_agent
                                                                              │
                                                                      remediation_agent
                                                                              │
                                                                          report_node ──> END
```

- **`infra_agent_node`** — runs Nmap (`nmap_tool`), enriches results with CVE lookups (`cve_tool`), retrieves a **cross-run memory summary** for this same target from SQLite scan history (see below), then asks the LLM (structured JSON output) — with both the CVE findings and the prior-run memory in context — whether findings justify simulating exploitation. This is the only node whose routing decision is made by an LLM call rather than deterministic logic.
- **`exploit_node`** — runs a safe, local post-exploitation simulation (privilege/logging checks) via `post_exploit_tool`.
- **`web_agent_node`** — orchestrates a real DAST pipeline: a real **OWASP ZAP v2** spider + active scan against a running ZAP proxy (with deduplicated, sanitized alerts), a real `nuclei` subprocess scan, passive proxy logging, and conditional delegation to a real `sqlmap` subprocess when an injection signature is suspected — see the fidelity note below for `sqlmap_tool`'s no-sqlmap-installed fallback.
- **`critic_agent_node`** — a **self-correction loop**: if the web scan returns zero findings and iteration count is below 2, it forces a retry with adjusted depth instead of silently proceeding with an empty result set.
- **`game_security_agent_node`** — runs five checks against the target: a proprietary game fuzzer via the adapter registry, WebSocket fuzzing, UDP netcode fuzzing (via `netcode_fuzz_tool`, which wraps `scanner/netcode_fuzzer.py`'s blocking-socket `GameNetcodeFuzzer` — see fidelity note), a microtransaction/matchmaking logic audit, and an optional **Mobile SAST** pass (`mobile_sast_tool`) against a companion Android app's manifest/source when supplied via `--mobile-manifest`/`--mobile-source` — merging all findings into the shared vulnerability list.
- **`remediation_agent_node`** — feeds all accumulated vulnerabilities to `remediation_tool`, a **rule-based template generator** (not LLM-backed — it pattern-matches on risk level to produce fix guidance), and appends the result as its own finding entry. A genuinely LLM-backed critic (`local_llm_critic_tool`, local Ollama) exists in `orchestration/tools.py` but is not currently wired into any node in `graph.py`.
- **`report_node`** — compiles the final Markdown report from the complete finding set.

State (`PentestState`) is a single `TypedDict` threaded through every node — scan results, enriched CVEs, web vulnerabilities, post-exploit data, a reasoning `history` trail, and loop-control fields (`iteration_count`, `critic_feedback`, `requires_remediation`).

### Tool Adapter Registry Pattern

Rather than calling scanners directly, game-security tooling is invoked through a `ToolRegistry` (`core/adapters.py`) built on a `BaseToolAdapter` abstract base class (`name` property + `execute()` method). Concrete adapters — e.g. `ProprietaryGameFuzzerAdapter` (`adapters/proprietary_game_fuzzer.py`) — implement `execute()` and return a validated Pydantic `ToolExecutionResult` (`core/schemas.py`): `tool_name`, `target`, `status`, a list of typed `VulnerabilityRecord`s, and raw metadata. `core/init_framework.py`'s `initialize_osaf_tools()` registers all available adapters into a `global_registry` singleton at graph load time. This decouples orchestration nodes from concrete tool implementations: swapping or adding a scanner means writing and registering a new adapter class, not touching graph logic.

**Honest note on fidelity:** `ProprietaryGameFuzzerAdapter`, the orchestration-level `WebSocketGameFuzzer` (`orchestration/websocket_fuzzer.py`), `scanner/microtransaction_analyzer.py`, and the gRPC-reflection check inside `scanner/game_api_analyzer.py` currently return **structured, hardcoded findings** rather than live fuzzing/testing output — they demonstrate the adapter contract and downstream data flow, not production detection logic. `proxy_logger_tool` writes a real JSON log file but, as called from `web_agent_node`, always logs the same hardcoded "simulated interception" entry rather than genuine captured traffic. `sqlmap_tool`'s fallback (when `sqlmap` isn't installed) always reports `vulnerable: True` with a canned payload — useful for pipeline demos, but not a neutral "unknown" result.

In contrast, `web_vuln_scanner_tool` (real OWASP ZAP v2 API: spider + active scan + alert dedup), `nuclei_tool` and `sqlmap_tool` (real subprocess calls when the binaries are present), `InGameEconomyAuditor` (`core/economy_auditor.py`, async `httpx` concurrent POSTs), `scanner/netcode_fuzzer.py`'s `GameNetcodeFuzzer` (the one actually wired into the graph via `netcode_fuzz_tool`), `scanner/game_api_analyzer.py`'s rate-limit header check, `scanner/mobile_analyzer.py`, `scanner/game_script_sast.py`, `scanner/ghidra_headless_analyzer.py` (with a real string-extraction fallback), and `enrichment/nmap_integration.py` all perform genuine analysis or network interaction and derive their verdict from actual results.

Worth noting separately: `orchestration/tools.py` also defines `economy_auditor_tool` (wrapping the real `InGameEconomyAuditor`), `netcode_desync_fuzzer_tool` (wrapping `core/netcode_fuzzer.py`'s asyncio-based `NetcodeDesyncFuzzer`), and `local_llm_critic_tool` (real local Ollama call) — all three are fully implemented but **not currently invoked by any node in `graph.py`**, i.e. they're available tools not yet wired into the live pipeline.

**Full tool inventory (`orchestration/tools.py`):**

| Tool | Backing implementation | Fidelity | Wired into `graph.py`? |
|---|---|---|---|
| `nmap_tool` | `scanner/nmap_integration.py` | Real subprocess | ✅ |
| `cve_tool` | `enrichment/cve_lookup.py` | Real RAG + dict fallback | ✅ |
| `post_exploit_tool` | `post_exploitation/adversary_sim.py` | Real local recon | ✅ |
| `web_vuln_scanner_tool` | OWASP ZAP v2 API | Real (needs local ZAP proxy) | ✅ |
| `nuclei_tool` | `nuclei` subprocess | Real (needs `nuclei` installed) | ✅ |
| `sqlmap_tool` | `sqlmap` subprocess | Real, but always-vulnerable fallback if `sqlmap` missing | ✅ |
| `mobile_sast_tool` | `scanner/mobile_analyzer.py` | Real regex SAST | ✅ (in `game_security_agent_node`, gated on optional `--mobile-manifest`) |
| `game_api_sast_tool` | `scanner/game_api_analyzer.py` | Real HTTP check + mocked gRPC check | Not currently called by a node |
| `websocket_fuzz_tool` | `orchestration/websocket_fuzzer.py` | Hardcoded findings | ✅ |
| `netcode_fuzz_tool` | `scanner/netcode_fuzzer.py` (`GameNetcodeFuzzer`) | Real blocking-socket UDP | ✅ |
| `game_script_sast_tool` | `scanner/game_script_sast.py` | Real regex secret scan | Not currently called by a node |
| `microtransaction_audit_tool` | `scanner/microtransaction_analyzer.py` | Hardcoded findings | ✅ |
| `economy_auditor_tool` | `core/economy_auditor.py` | Real async concurrency test | Not currently called by a node |
| `netcode_desync_fuzzer_tool` | `core/netcode_fuzzer.py` (`NetcodeDesyncFuzzer`) | Real asyncio UDP | Not currently called by a node |
| `ghidra_sast_tool` | `scanner/ghidra_headless_analyzer.py` | Real (headless) + real string-extraction fallback | Not currently called by a node |
| `local_llm_critic_tool` | `core/llm_provider.py` (Ollama) | Real local LLM call | Not currently called by a node |
| `proxy_logger_tool` | inline | Writes real file, hardcoded log content | ✅ |
| `remediation_tool` | inline | Rule-based template (not LLM) | ✅ |
| `report_generator_tool` | inline | Real Markdown writer | ✅ |
| `benchmark_evaluation_tool` | `orchestration/benchmarker.py` | Real | Called from `main_agentic.py`, not `graph.py`'s node flow |

Several other fully-implemented, real tools (game API SAST, game-script secret scanning, Ghidra binary analysis, the real economy/netcode auditors, the local LLM critic) exist and pass their own tests but aren't yet called anywhere in the live LangGraph flow — Mobile SAST has since been wired in (see above); a natural next step is wiring in the rest via `game_security_agent_node` or dedicated new nodes.

### Prompt-Injection Guardrails

`orchestration/sanitizer.py` implements a regex-based `PromptInjectionSanitizer` that runs over **every untrusted tool output** (scraped pages, banners, scan text) before it reaches the LLM context — matching common injection patterns (`"ignore previous instructions"`, fake `system:` blocks, embedded `<script>` tags, etc.), redacting matches, and wrapping the result in `<untrusted_tool_data>` boundary tags. This is applied explicitly in `infra_agent_node` before CVE findings are handed to the LLM for the exploit-recommendation decision.

### RAG-Backed CVE Knowledge Base

`core/rag_store.py` implements `CveRagStore`: a persistent **ChromaDB** collection indexed with local `SentenceTransformer` (`all-MiniLM-L6-v2`) embeddings. CVEs are upserted with severity/CVSS metadata, and `search_similar_cves()` performs semantic similarity search — allowing the framework to surface related historical CVEs for a new finding without another LLM round-trip.

### Local LLM Fallback Critic

`core/llm_provider.py` wraps a local **Ollama** model (default `llama3`, configurable via `OSAF_OLLAMA_MODEL`/`OLLAMA_BASE_URL`) through `langchain-ollama` (or `langchain-community` as a fallback import). `core/agent_tools_wiring.py`'s `get_ai_critic_review()` uses this to generate mitigation advice offline when a local model is available, and degrades gracefully to a rule-based message if Ollama isn't running — the framework never hard-fails on a missing local LLM.

### Cross-Run Memory Management

Beyond the single-run `PentestState`, OSAF persists a durable memory layer in SQLite (`database.py`): every completed scan is saved with its target, profile, vulnerability count, and full report. `get_target_history(target)` retrieves prior runs for the same target, and `summarize_target_memory(target)` condenses them into a short, LLM-ready text summary (timestamp, finding count, and top vulnerability names per prior run).

`infra_agent_node` consumes this automatically: if `prior_scan_context` isn't already set on the state, the node looks it up itself before making its exploit-recommendation call, and includes it directly in the LLM prompt — explicitly instructing the model to avoid redundant flags for already-known findings and to note anything recurring across runs. Because the lookup happens inside the node (not just at the CLI entrypoint), it works consistently whether the pipeline is invoked from `cli.py`, `main_agentic.py`, or in tests. `cli.py` additionally surfaces the retrieved memory in a visible console panel before each run, so the effect is observable end-to-end, not just internal state.

### Continuous Evaluation (MLOps)

`orchestration/benchmarker.py`'s `AgentBenchmarker` scores a run against a **ground-truth expected vulnerability count**:
- Deduplicates findings across heterogeneous tool output shapes (ZAP `risk`, RAG `severity`, SQLMap `vulnerable` flags, etc.) into a single set of unique High/Medium+ findings.
- Computes **Precision, Recall, and F1** against ground truth.
- Computes efficiency metrics — **seconds per finding** and **LLM tokens per finding**.
- Persists both a timestamped run file and a `latest_<target>.json` to `benchmarks/` for CI/CD trend tracking.

---

## 📂 Project Structure

```text
offensive-automation-framework/
│
├── cli.py                        # Primary CLI entrypoint (rich UI, SQLite history) → drives the LangGraph pipeline
├── main.py                       # Legacy linear entrypoint ("v2.0 Tiger Team Edition") — nmap + CVE + post-exploit, no LangGraph
├── main_agentic.py                # Standalone agentic entrypoint: runs the graph directly, prints reasoning trace, auto-invokes report + benchmark tools
├── database.py                    # SQLite scan-history persistence + cross-run memory (get_target_history, summarize_target_memory)
│
├── core/
│   ├── adapters.py                 # Tool Adapter Registry (global_registry)
│   ├── init_framework.py           # Adapter/tool bootstrap on graph load
│   ├── schemas.py                  # Pydantic models: VulnerabilityRecord, ToolExecutionResult
│   ├── agent_tools_wiring.py       # Wraps economy auditor / netcode fuzzer / local LLM critic as callable tools
│   ├── rag_store.py                # ChromaDB + SentenceTransformer CVE semantic search
│   ├── economy_auditor.py          # High-concurrency store race-condition auditor
│   ├── netcode_fuzzer.py           # UDP state-replication desync fuzzer
│   └── llm_provider.py             # Local Ollama LLM provider wrapper (offline critic fallback)
│
├── orchestration/
│   ├── graph.py                    # LangGraph StateGraph: node definitions + conditional routing
│   ├── state.py                    # PentestState TypedDict + initializer
│   ├── tools.py                    # LangChain @tool matrix — 18 tools (see below); ZAP/Nuclei/SQLMap are real, several are demo-fidelity
│   ├── sanitizer.py                # PromptInjectionSanitizer guardrail
│   ├── benchmarker.py              # AgentBenchmarker — Precision/Recall/F1 + efficiency metrics
│   ├── utils.py                    # JSON extraction & LLM output fallback parsing
│   └── websocket_fuzzer.py         # Real-time WebSocket protocol fuzzer
│
├── agents/
│   └── game_security_agent.py      # Standalone game-security node using the adapter registry
│
├── adapters/
│   └── proprietary_game_fuzzer.py  # Concrete adapter implementation for the game fuzzer (structured demo output)
│
├── scanner/
│   ├── game_api_analyzer.py        # Real HTTP checks for missing rate-limit headers; gRPC reflection check is currently mocked
│   ├── game_script_sast.py         # Real regex-based secret scanner for game scripts/config (API keys, tokens, Stripe keys)
│   ├── ghidra_headless_analyzer.py # Real Ghidra headless subprocess call, with a genuine string-extraction fallback if Ghidra isn't installed
│   ├── microtransaction_analyzer.py # Static/hardcoded findings (not live-tested) — distinct from the real testing in core/economy_auditor.py
│   ├── mobile_analyzer.py          # Real regex SAST on Android manifests & source (cleartext traffic, debug flag, permissions, hardcoded secrets)
│   ├── netcode_fuzzer.py           # Separate blocking-socket UDP fuzzer (GameNetcodeFuzzer) — distinct implementation from core/netcode_fuzzer.py's asyncio version
│   ├── nmap_integration.py         # Real `nmap -sV` subprocess + XML parsing (used by the legacy main.py path)
│   └── port_scanner.py             # Native-socket TCP port scanner, a lighter alternative to Nmap
├── enrichment/cve_lookup.py        # Legacy-path RAG CVE lookup (ChromaDB + SentenceTransformer) w/ dictionary fallback
├── post_exploitation/adversary_sim.py  # Safe local system recon: OS, user, cwd, /tmp writability, privilege level
├── reporting/json_export.py        # JSON report writer for the legacy pipeline
│
├── benchmarks/                     # AgentBenchmarker JSON output (per-run + latest)
├── reports/                        # Generated Markdown pentest reports
├── logs/proxy_traffic/             # Captured HTTP/HTTPS proxy transaction logs
├── cve_vector_store/                # ChromaDB persistent CVE embeddings
├── tests/                          # pytest suite (44/44 passing)
├── Dockerfile / docker-compose.yml
└── .github/workflows/ci.yml        # GitHub Actions CI (lint via ruff, tests)
```

---

## 🛠️ Installation & Setup

```bash
sudo apt update && sudo apt install nmap sqlmap -y

cd offensive-automation-framework
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
GEMINI_API_KEY="your_actual_gemini_api_key_here"
```

---

## 🚀 Usage

**Run the full agentic pipeline:**
```bash
python3 cli.py --target 127.0.0.1 --profile full
```
`--profile` accepts `full`, `web`, `infra`, or `websocket`.

**Run with an optional Mobile SAST pass** (for a companion Android app):
```bash
python3 cli.py --target 127.0.0.1 --mobile-manifest ./AndroidManifest.xml --mobile-source ./strings.xml
```
If `--mobile-manifest` is omitted, `game_security_agent_node` skips the mobile scan entirely — this keeps default runs unchanged.

**See cross-run memory in action** — run the same target twice; the second run prints a "🧠 Prior Scan Memory" panel summarizing the first run's findings, and that summary is fed to the LLM's exploit-recommendation prompt:
```bash
python3 cli.py --target 127.0.0.1
python3 cli.py --target 127.0.0.1
```

**View local scan history (SQLite-backed):**
```bash
python3 cli.py --history
```

**Run the standalone agentic entrypoint** (invokes the LangGraph pipeline directly, without the `cli.py`/SQLite wrapper, and auto-runs the report + benchmark tools at the end):
```bash
python3 main_agentic.py 127.0.0.1
```

**Run the legacy linear scan** (no LangGraph, faster smoke-test path — Nmap → RAG/dictionary CVE lookup → optional post-exploit simulation → JSON export):
```bash
python3 main.py -t 127.0.0.1 --sim-post
```
This path has its own independent RAG CVE lookup (`enrichment/cve_lookup.py`) with a ChromaDB+SentenceTransformer implementation and a hardcoded dictionary fallback (`FALLBACK_VULN_DB`) if the vector store fails to initialize — separate from the `core/rag_store.py` store used by the agentic pipeline.

**Run the test suite:**
```bash
PYTHONPATH=. pytest -v
```

**Docker:**
```bash
docker compose up --build
```

---

## 📊 Outputs

| Artifact | Location | Contents |
|---|---|---|
| Executive report | `reports/pentest_report_<target>.md` | All unique findings, severity, remediation patches |
| Benchmark evaluation | `benchmarks/run_<target>_<timestamp>.json`, `benchmarks/latest_<target>.json` | Precision/Recall/F1, tokens/finding, seconds/finding |
| Scan history | SQLite (`reports/osaf_history.db`) | Target, profile, vuln count, full report JSON per run |
| Proxy traffic | `logs/proxy_traffic/traffic_<timestamp>.json` | Intercepted HTTP/HTTPS request/response cycles |
| CVE vector store | `cve_vector_store/` | Persistent ChromaDB collection for CVE semantic search |

---

## ⚠️ Security & Ethical Disclaimer

This framework is developed strictly for educational, authorized penetration testing, and defensive engineering evaluation. It does not contain pre-packaged operational exploits or weaponized malware payloads. Always obtain written authorization before scanning any infrastructure.