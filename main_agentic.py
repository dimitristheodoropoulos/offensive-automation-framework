"""
Entry point για την agentic έκδοση του OSAF.
Χρήση:
    python3 main_agentic.py 127.0.0.1
"""
import sys
import time
from orchestration.graph import agent_app
from orchestration.state import new_state

# Εισαγωγή των νέων εργαλείων αυτοματοποίησης και benchmarking
from orchestration.tools import report_generator_tool, benchmark_evaluation_tool


def run_agent(target_ip: str):
    print(f"[*] Starting OSAF Agentic Execution for target: {target_ip}")
    
    # Έναρξη χρονομέτρησης για το Benchmarking Tool
    start_time = time.time()
    
    # 1. Εκτέλεση του LangGraph state machine
    initial_state = new_state(target_ip)
    result = agent_app.invoke(initial_state)

    # Υπολογισμός συνολικού χρόνου εκτέλεσης
    end_time = time.time()
    execution_time = end_time - start_time

    print("\n=== AGENT REASONING TRACE ===")
    for step in result.get("history", []):
        print(f"- {step}")

    print(f"\n=== FINAL ACTION: {result.get('next_action')} ===")

    # 2. Συγκέντρωση όλων των ευρημάτων (Web & Network) για την αναφορά
    all_vulnerabilities = []

    # Ανάκτηση Web Vulnerabilities (από το OWASP ZAP Node)
    if result.get("web_vulnerabilities"):
        print(f"\n[+] Web vulnerabilities found: {len(result['web_vulnerabilities'])}")
        for v in result["web_vulnerabilities"]:
            print(f"  [{v.get('risk')}] {v.get('name')} @ {v.get('url')}")
            all_vulnerabilities.append(v)

    # Ανάκτηση Network Vulnerabilities / CVEs (από το Nmap & CVE Lookup Nodes)
    network_vulns = result.get("cves_found") or result.get("vulnerabilities") or []
    if network_vulns:
        print(f"[+] Network vulnerabilities/CVEs found: {len(network_vulns)}")
        for nv in network_vulns:
            all_vulnerabilities.append(nv)

    print("\n=== AUTOMATED POST-RUN WORKFLOW (A-Z) ===")
    
    # 3. Αυτόματο πέρασμα των δεδομένων στο report_generator_tool
    print("[*] Constructing professional assessment report...")
    report_status = report_generator_tool.invoke({
        "vulnerabilities": all_vulnerabilities,
        "target": target_ip
    })
    print(f"[+] {report_status}")

    # 4. Αυτόματο πέρασμα των δεδομένων στο benchmark_evaluation_tool
    expected_vulns_in_lab = 3 
    
    print("[*] Running execution metrics against development baseline...")
    benchmark_results = benchmark_evaluation_tool.invoke({
        "discovered_vulns": all_vulnerabilities,
        "target_name": target_ip,
        "expected_vulns_count": expected_vulns_in_lab,
        "execution_time_seconds": execution_time,
        "tokens_used": result.get("tokens_used", 0)
    })
    
    # Δυναμική εκτύπωση των metrics χωρίς εξάρτηση από συγκεκριμένα κλειδιά
    if "error" not in benchmark_results:
        print("[+] Benchmark Evaluation Saved to JSON!")
        for key, value in benchmark_results.items():
            print(f"    - {key}: {value}")
    else:
        print(f"[-] Benchmark Error: {benchmark_results.get('error')}")

    return result


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_agent(target)