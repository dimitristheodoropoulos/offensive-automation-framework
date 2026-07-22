import sys
import os

# Προσθήκη του root directory στο PYTHONPATH για τα imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestration.tools import cve_tool


def test_cve_tool_execution():
    print("[*] Starting Unit Test for cve_tool & RAG CVE Lookup...")

    # Δείγμα υπηρεσιών που επιστρέφει το Nmap Tool
    test_services = [
        {"port": 22, "service": "ssh"},
        {"port": 80, "service": "http"},
        {"port": 8080, "service": "http-proxy"},
        {"port": 9999, "service": "unknown_custom_service"}
    ]

    # Εκτέλεση του LangChain Tool
    results = cve_tool.invoke({"services": test_services})

    print("\n[+] Verification Results:")
    print("-" * 60)
    for res in results:
        port = res.get("port")
        service = res.get("service")
        severity = res.get("severity")
        cves = res.get("cves")
        print(f" Port {port:<5} | Service: {service:<15} | Severity: {severity:<8} | CVEs: {cves}")
    print("-" * 60)

    # Έλεγχοι εγκυρότητας (Assertions)
    assert isinstance(results, list), "Error: Results must be a list"
    assert len(results) == len(test_services), "Error: Input/Output item count mismatch"
    assert "cves" in results[0], "Error: Missing 'cves' key in output schema"

    print("\n[✓] All unit test assertions passed successfully!")


if __name__ == "__main__":
    test_cve_tool_execution()