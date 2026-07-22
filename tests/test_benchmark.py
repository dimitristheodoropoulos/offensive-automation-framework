import sys
import os
import json

# Προσθήκη του root directory στο PYTHONPATH για τα imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestration.benchmarker import AgentBenchmarker


def test_benchmarker_execution():
    print("[*] Starting Unit Test for AgentBenchmarker...")

    target_name = "test_juice_shop"
    expected_vulns_ground_truth = 3

    # Προσομοίωση ευρημάτων από διαφορετικά εργαλεία (ZAP, Nuclei, RAG CVE)
    mock_discovered_alerts = [
        {"name": "SQL Injection - Search Field", "risk": "High", "url": "http://127.0.0.1:3000/#/search"},
        {"name": "Cross-Site Scripting (Reflected XSS)", "risk": "Medium", "url": "http://127.0.0.1:3000/#/contact"},
        {"service": "ssh", "cves": ["CVE-2024-6387"], "severity": "Critical", "port": 22},
        {"name": "Informational Banner Leakage", "risk": "Low", "url": "http://127.0.0.1:3000"}  # Θα αγνοηθεί (Low risk)
    ]

    benchmarker = AgentBenchmarker(
        target_name=target_name, 
        expected_vulns_count=expected_vulns_ground_truth
    )

    # Εκτέλεση αξιολόγησης με εικονικό χρόνο εκτέλεσης (15.4s) και tokens (1450)
    report = benchmarker.evaluate_run(
        discovered_alerts=mock_discovered_alerts,
        execution_time=15.4,
        tokens_used=1450
    )

    # Έλεγχοι εγκυρότητας (Assertions)
    assert isinstance(report, dict), "Error: Report must be a dictionary"
    assert report["Target"] == target_name, "Error: Target name mismatch"
    assert report["Unique High/Medium Detected"] == 3, f"Expected 3 unique findings, got {report['Unique High/Medium Detected']}"
    assert report["Detection Metrics"]["Recall Rate (%)"] == 100.0, "Expected 100.0% Recall Rate"
    assert report["Detection Metrics"]["Precision Rate (%)"] == 100.0, "Expected 100.0% Precision Rate"
    
    # Έλεγχος δημιουργίας αρχείου JSON
    latest_file = f"benchmarks/latest_{target_name}.json"
    assert os.path.exists(latest_file), f"Error: Benchmark JSON file {latest_file} was not generated"

    # Επαλήθευση περιεχομένου του αποθηκευμένου JSON
    with open(latest_file, "r", encoding="utf-8") as f:
        saved_data = json.load(f)
        assert saved_data["Target"] == target_name

    print("[✓] All benchmarker unit test assertions passed successfully!")


if __name__ == "__main__":
    test_benchmarker_execution()