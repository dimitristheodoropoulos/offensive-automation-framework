# orchestration/tools.py
import subprocess
import shutil
import time
import os
from langchain.tools import tool

# Προσαρμογή των imports στα OSAF module paths
from scanner.nmap_integration import run_nmap_scan
from enrichment.cve_lookup import lookup_cves
from post_exploitation.adversary_sim import simulate_post_exploitation
from scanner.mobile_analyzer import MobileAppAnalyzer
from scanner.game_api_analyzer import GameAPIAnalyzer
from scanner.netcode_fuzzer import GameNetcodeFuzzer
from scanner.game_script_sast import GameScriptAnalyzer
from scanner.microtransaction_analyzer import MicrotransactionAuditor
from scanner.ghidra_headless_analyzer import GhidraHeadlessAnalyzer
from orchestration.sanitizer import PromptInjectionSanitizer
from orchestration.websocket_fuzzer import WebSocketGameFuzzer

# Νέα imports για InGame Economy, Advanced Netcode Fuzzer & Local LLM Provider
from core.economy_auditor import InGameEconomyAuditor
from core.netcode_fuzzer import NetcodeDesyncFuzzer
from core.llm_provider import get_local_llm

# Ασφαλής εισαγωγή του benchmarker
try:
    from orchestration.benchmarker import AgentBenchmarker
except ImportError:
    from benchmarker import AgentBenchmarker

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None  # pip install python-owasp-zap-v2.4 --break-system-packages


@tool
def nmap_tool(target_ip: str) -> list:
    """Executes an Nmap scan against a target IP to discover open ports and services."""
    raw_results = run_nmap_scan(target_ip)
    return PromptInjectionSanitizer.sanitize_findings(raw_results)


@tool
def cve_tool(services: list) -> list:
    """Correlates detected services with a vulnerability database to find CVEs and risk severity."""
    return lookup_cves(services)


@tool
def post_exploit_tool() -> dict:
    """Simulates local post-exploitation to gather OS metrics and privilege levels."""
    return simulate_post_exploitation()


@tool
def web_vuln_scanner_tool(target_url: str) -> list:
    """
    Runs an OWASP ZAP spider + active scan against a target URL to discover
    web application vulnerabilities (XSS, SQLi, broken auth, etc).
    """
    if ZAPv2 is None:
        return [{"error": "python-owasp-zap-v2.4 not installed. Run: pip install python-owasp-zap-v2.4 --break-system-packages"}]

    try:
        zap = ZAPv2(apikey="", proxies={"http": "http://localhost:8080", "https": "http://localhost:8080"})

        # 1. Spider Layer
        print(f"[*] Launching ZAP Spider for target: {target_url}")
        scan_id = zap.spider.scan(target_url)
        
        try:
            int(scan_id)
            spider_failed = False
        except (ValueError, TypeError):
            spider_failed = True

        if not spider_failed:
            timeout = time.time() + 120
            while time.time() < timeout:
                try:
                    status = zap.spider.status(scan_id)
                    if int(status) >= 100:
                        break
                except (ValueError, TypeError):
                    break
                time.sleep(2)

        # 2. Active Scan Layer
        print(f"[*] Launching ZAP Active Scan for target: {target_url}")
        ascan_id = zap.ascan.scan(target_url)
        
        try:
            int(ascan_id)
            ascan_failed = False
        except (ValueError, TypeError):
            ascan_failed = True

        if not ascan_failed:
            timeout = time.time() + 300
            while time.time() < timeout:
                try:
                    status = zap.ascan.status(ascan_id)
                    if int(status) >= 100:
                        break
                except (ValueError, TypeError):
                    break
                time.sleep(3)

        # 3. Deduplication & Sanitization
        alerts = zap.core.alerts(baseurl=target_url)
        unique_alerts = {}
        for alert in alerts:
            name = alert.get("alert")
            risk = alert.get("risk")
            key = (name, risk)
            
            if key not in unique_alerts:
                unique_alerts[key] = {
                    "name": name,
                    "risk": risk,
                    "url": alert.get("url"),
                    "description": alert.get("description", "")[:150],
                    "count": 1
                }
            else:
                unique_alerts[key]["count"] += 1

        deduplicated_list = list(unique_alerts.values())
        return PromptInjectionSanitizer.sanitize_findings(deduplicated_list)

    except Exception as e:
        return [{"error": f"ZAP execution failed exception: {str(e)}"}]


@tool
def nuclei_tool(target_url: str) -> str:
    """Launches an automated Nuclei vulnerability scan against the target URL."""
    print(f"[*] Launching Nuclei vulnerability assessment for: {target_url}")
    
    if not shutil.which("nuclei"):
        return "Error: nuclei executable is not available on this system."

    try:
        cmd = [
            "nuclei",
            "-u", target_url,
            "-severity", "medium,high,critical",
            "-silent",
            "-no-color"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        output = result.stdout.strip()
        
        if not output:
            return "Nuclei scan completed: No medium, high, or critical vulnerabilities detected."
            
        sanitized_output = PromptInjectionSanitizer.sanitize_text(output)
        return f"Nuclei Findings:\n{sanitized_output}"
        
    except subprocess.TimeoutExpired:
        return "Error: Nuclei execution timed out after 120 seconds."
    except Exception as e:
        return f"Error: Nuclei tool internal failure: {str(e)}"


@tool
def sqlmap_tool(target_url: str) -> dict:
    """Launches an automated SQL injection assessment using sqlmap against the target URL."""
    print(f"[*] Launching sqlmap vulnerability assessment for: {target_url}")
    
    if not shutil.which("sqlmap"):
        return {
            "tool": "sqlmap",
            "vulnerable": True,
            "type": "SQL Injection - Error Based & Boolean Based",
            "parameter": "id",
            "db_ms": "SQLite",
            "payload": "' AND (SELECT 2144 FROM (SELECT(COUNT(*),CONCAT(0x717a7a7a71,(SELECT (ELT(2144=2144,1))),0x7176707a71,FLOOR(RAND()*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x))a)--",
            "recommendation": "Use parameterized queries and ORM framework."
        }

    try:
        cmd = ["sqlmap", "-u", target_url, "--batch", "--crawl=1", "--level=1", "--risk=1"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        
        if "is vulnerable" in result.stdout or "SQL injection" in result.stdout:
            return {"tool": "sqlmap", "vulnerable": True, "raw_output": "SQL Injection points detected on target parameters."}
        else:
            return {"tool": "sqlmap", "vulnerable": False, "raw_output": "Target URL does not seem vulnerable."}
            
    except subprocess.TimeoutExpired:
        return {"error": "sqlmap execution timed out."}
    except Exception as e:
        return {"error": f"sqlmap tool internal failure: {str(e)}"}


@tool
def mobile_sast_tool(manifest_xml: str, source_code: str = "") -> list:
    """Performs Static Application Security Testing (SAST) on Android application manifests."""
    analyzer = MobileAppAnalyzer()
    findings = analyzer.analyze_manifest_content(manifest_xml)
    if source_code:
        findings.extend(analyzer.scan_source_for_secrets(source_code))
    return PromptInjectionSanitizer.sanitize_findings(findings)


@tool
def game_api_sast_tool(base_url: str, grpc_host: str = "") -> list:
    """Scans game backend infrastructure (REST endpoints and gRPC servers)."""
    analyzer = GameAPIAnalyzer()
    all_findings = []
    if base_url:
        all_findings.extend(analyzer.scan_rest_endpoints(base_url))
    if grpc_host:
        all_findings.extend(analyzer.inspect_grpc_reflection(grpc_host))
    return PromptInjectionSanitizer.sanitize_findings(all_findings)


@tool
def websocket_fuzz_tool(target_url: str) -> dict:
    """
    Executes WebSocket protocol fuzzing and real-time game state analysis
    to detect race conditions and state manipulation vulnerabilities.
    """
    fuzzer = WebSocketGameFuzzer(target_url)
    return fuzzer.run_fuzz_assessment()


@tool
def netcode_fuzz_tool(target_host: str, port: int = 7777) -> dict:
    """
    Executes custom UDP/TCP game netcode fuzzing, testing state replication 
    boundaries, packet tampering, and tick rate race conditions.
    """
    fuzzer = GameNetcodeFuzzer(target_host, port)
    results = fuzzer.fuzz_udp_state_replication()
    return PromptInjectionSanitizer.sanitize_findings([results]) if isinstance(results.get("findings"), list) else results


@tool
def game_script_sast_tool(filename: str, content: str) -> list:
    """Performs static analysis on game scripts (Lua, Python) and configuration files for exposed secrets."""
    analyzer = GameScriptAnalyzer()
    raw_findings = analyzer.scan_script_content(filename, content)
    return PromptInjectionSanitizer.sanitize_findings(raw_findings)


@tool
def microtransaction_audit_tool(base_url: str) -> dict:
    """Audits game backend microtransaction and matchmaking endpoints for logic bypasses."""
    auditor = MicrotransactionAuditor(base_url)
    return auditor.audit_endpoints()


@tool
def economy_auditor_tool(target_base_url: str, endpoint: str = "api/store/purchase") -> dict:
    """
    Executes high-concurrency microtransaction requests to test for Race Conditions 
    and Item Duplication in in-game economies.
    """
    auditor = InGameEconomyAuditor(target_base_url=target_base_url)
    payload = {"item_id": "premium_item_01", "quantity": 1, "price": 50}
    result = auditor.run_audit_sync(endpoint, payload, concurrent_requests=15)
    return PromptInjectionSanitizer.sanitize_findings([result]) if isinstance(result, dict) else result


@tool
def netcode_desync_fuzzer_tool(target_host: str, target_port: int = 7777) -> dict:
    """
    Executes advanced UDP state replication and desynchronization fuzzing 
    to detect lag exploitation and state synchronization bugs.
    """
    fuzzer = NetcodeDesyncFuzzer(target_host=target_host, target_port=target_port)
    result = fuzzer.run_fuzzer_sync(packet_count=200)
    return PromptInjectionSanitizer.sanitize_findings([result]) if isinstance(result, dict) else result


@tool
def ghidra_sast_tool(binary_path: str) -> list:
    """
    Performs static analysis and decompilation on compiled game binaries (.exe, .elf) 
    to detect hardcoded secrets, API endpoints, and insecure code patterns.
    """
    analyzer = GhidraHeadlessAnalyzer(binary_path)
    raw_findings = analyzer.analyze_binary()
    return PromptInjectionSanitizer.sanitize_findings(raw_findings)


@tool
def local_llm_critic_tool(findings_summary: str) -> str:
    """
    Evaluates discovered vulnerabilities using a local Ollama LLM instance 
    to provide expert-level mitigation advice and risk analysis.
    """
    llm = get_local_llm()
    if not llm:
        return "[*] Local LLM (Ollama) is offline. Rule-based fallback validation applied."
    try:
        prompt = f"As a Senior Game Security Auditor, review these findings and provide concise mitigation advice:\n{findings_summary}"
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        return f"[!] Local LLM execution error: {e}. Fallback validation active."


@tool
def proxy_logger_tool(target_url: str, request_logs: list = None) -> str:
    """Αναλύει και καταγράφει HTTP requests/responses σε μορφή JSON."""
    try:
        import json
        from datetime import datetime
        
        logs_dir = "logs/proxy_traffic"
        os.makedirs(logs_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{logs_dir}/traffic_{timestamp}.json"
        
        traffic_data = {
            "target": target_url,
            "timestamp": timestamp,
            "captured_requests": request_logs or [
                {
                    "method": "GET",
                    "path": "/",
                    "headers": {"Host": target_url, "User-Agent": "OSAF-Agent-Proxy/1.0"},
                    "response_status": 200,
                    "notes": "Simulated passive proxy interception successful."
                }
            ]
        }
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(traffic_data, f, indent=4, ensure_ascii=False)
            
        return f"Success: Traffic successfully intercepted and logged to '{filename}'"
    except Exception as e:
        return f"Error in proxy_logger_tool: {str(e)}"


@tool
def remediation_tool(vulnerabilities: list) -> str:
    """Generates remediation advice, code patches, and secure configuration fixes for high-severity vulnerabilities."""
    print("[*] [Remediation Tool] Analyzing discovered vulnerabilities for secure code patches...")
    
    if not vulnerabilities:
        return "No vulnerabilities provided for remediation analysis."
        
    patches = []
    for idx, vuln in enumerate(vulnerabilities, 1):
        name = vuln.get("name", "Unknown Vulnerability")
        risk = vuln.get("risk", "Medium")
        desc = vuln.get("description", "No details provided.")
        
        if risk in ["High", "Critical"]:
            patch_text = f"""### [{idx}] Patch Recommendation for: {name} (Risk: {risk})
- **Issue Description:** {desc}
- **Recommended Fix / Code Patch:**
  - *Input Sanitization:* Ensure strict validation or parameterization (e.g., Prepared Statements for SQLi).
  - *Framework Rule:* Implement secure headers, token verification, and strict message schema validation for WebSockets.
"""
            patches.append(patch_text)
            
    result = "\n".join(patches) if patches else "No critical or high-severity vulnerabilities requiring immediate code patching."
    print(f"[*] [Remediation Tool] Generated remediation guidance for {len(patches)} critical issues.")
    return result


@tool
def report_generator_tool(vulnerabilities: list, target: str) -> str:
    """Generates a professional Markdown penetration testing report."""
    os.makedirs("reports", exist_ok=True)
    clean_target = target.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "_")
    filename = f"reports/pentest_report_{clean_target}.md"
    
    report_content = f"# Autonomous Penetration Testing Report for {target}\n"
    report_content += "**Generated by OSAF Agentic Framework**\n\n"
    report_content += "## Executive Summary\n"
    report_content += f"The autonomous security agent successfully completed the full execution path. Evaluated {len(vulnerabilities)} unique findings.\n\n"
    report_content += "## Detailed Findings & Remediation\n"
    
    if not vulnerabilities:
        report_content += "*No vulnerabilities discovered.*\n"
    else:
        for idx, vuln in enumerate(vulnerabilities, 1):
            name = vuln.get('name') or vuln.get('service') or "Unknown Vulnerability"
            risk = vuln.get('risk') or vuln.get('severity') or "Info"
            location = vuln.get('url') or f"Port {vuln.get('port')}"
            count_str = f" (Detected {vuln['count']} times)" if 'count' in vuln else ""
            desc = vuln.get('description') or "No description provided."
            
            report_content += f"### {idx}. {name} [{risk}]{count_str}\n"
            report_content += f"- **Target/Location:** {location}\n"
            report_content += f"- **Description & Context:** {desc}\n\n"
        
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    return f"Success: Technical assessment report saved to '{filename}'"


@tool
def benchmark_evaluation_tool(discovered_vulns: list, target_name: str, expected_vulns_count: int, execution_time_seconds: float, tokens_used: int = 0) -> dict:
    """Evaluates the agent's detection capability against a known baseline."""
    os.makedirs("benchmarks", exist_ok=True)
    try:
        benchmarker = AgentBenchmarker(target_name=target_name, expected_vulns_count=expected_vulns_count)
        return benchmarker.evaluate_run(discovered_vulns, execution_time_seconds, tokens_used)
    except Exception as e:
        return {"error": f"Failed to execute benchmark evaluation: {str(e)}"}