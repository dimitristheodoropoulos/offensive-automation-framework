# orchestration/benchmarker.py
import json
import os
from datetime import datetime
from typing import List, Dict, Any

class AgentBenchmarker:
    def __init__(self, target_name: str, expected_vulns_count: int):
        self.target_name = target_name
        self.expected_vulns_count = expected_vulns_count  # Ground Truth (Συνολικός αναμενόμενος αριθμός ευπαθειών)

    def _extract_high_medium_findings(self, discovered_alerts: List[Dict[str, Any]]) -> set:
        """
        Εξάγει μοναδικά ευρήματα Υψηλού/Μεσαίου κινδύνου.
        Υποστηρίζει πολλαπλά formats εξόδου από διαφορετικά εργαλεία (ZAP, Nuclei, SQLMap, RAG CVE).
        """
        unique_findings = set()
        
        for alert in discovered_alerts:
            if not isinstance(alert, dict):
                continue
                
            # Έλεγχος επιπέδου επικινδυνότητας (Risk / Severity)
            risk = str(alert.get("risk") or alert.get("severity") or "").capitalize()
            
            is_critical_or_high = risk in ["Critical", "High", "Medium"]
            has_cves = bool(alert.get("cves"))
            is_vulnerable_flag = alert.get("vulnerable", False)
            
            if is_critical_or_high or has_cves or is_vulnerable_flag:
                name = alert.get("name") or alert.get("service") or alert.get("type") or "Unknown Security Vector"
                unique_findings.add(name)
                
        return unique_findings

    def evaluate_run(self, discovered_alerts: List[Dict[str, Any]], execution_time: float, tokens_used: int = 0) -> Dict[str, Any]:
        """
        Αξιολογεί την απόδοση του agent υπολογίζοντας Recall, Precision,
        F1-Score, καθώς και μετρικές αποδοτικότητας (Tokens/Vuln, Seconds/Vuln).
        """
        os.makedirs("benchmarks", exist_ok=True)
        
        unique_findings = self._extract_high_medium_findings(discovered_alerts)
        unique_vulns = len(unique_findings)
        
        # 1. Βασικοί Δείκτες Αξιολόγησης (Ground Truth Comparison)
        tp = min(unique_vulns, self.expected_vulns_count) if self.expected_vulns_count > 0 else unique_vulns
        fp = max(0, unique_vulns - self.expected_vulns_count) if self.expected_vulns_count > 0 else 0
        
        recall = (tp / self.expected_vulns_count * 100) if self.expected_vulns_count > 0 else (100.0 if unique_vulns > 0 else 0.0)
        precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        
        # 2. Efficiency Metrics
        sec_per_vuln = round(execution_time / unique_vulns, 2) if unique_vulns > 0 else 0.0
        tokens_per_vuln = round(tokens_used / unique_vulns, 1) if unique_vulns > 0 else 0.0
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        benchmark_report = {
            "Target": self.target_name,
            "Timestamp": timestamp,
            "Execution Time (s)": round(execution_time, 2),
            "LLM Tokens Expended": tokens_used,
            "Unique High/Medium Detected": unique_vulns,
            "Ground Truth Expected": self.expected_vulns_count,
            "Detection Metrics": {
                "Recall Rate (%)": round(recall, 2),
                "Precision Rate (%)": round(precision, 2),
                "F1-Score (%)": round(f1_score, 2)
            },
            "Efficiency Metrics": {
                "Seconds per Finding": sec_per_vuln,
                "Tokens per Finding": tokens_per_vuln
            },
            "Discovered Finding Vector Names": list(unique_findings)
        }
        
        # Αποθήκευση ιστορικού run & ενημέρωση του 'latest'
        run_file = f"benchmarks/run_{self.target_name}_{timestamp}.json"
        latest_file = f"benchmarks/latest_{self.target_name}.json"
        
        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(benchmark_report, f, indent=4, ensure_ascii=False)
            
        with open(latest_file, "w", encoding="utf-8") as f:
            json.dump(benchmark_report, f, indent=4, ensure_ascii=False)

        print("\n" + "="*55)
        print(f"📊 [BENCHMARK EVALUATION] Target: {self.target_name}")
        print("="*55)
        print(f"• Execution Time     : {execution_time:.2f}s")
        print(f"• LLM Tokens Used    : {tokens_used}")
        print(f"• Unique Vulns Found : {unique_vulns} / {self.expected_vulns_count}")
        print(f"• Recall Rate        : {recall:.2f}%")
        print(f"• F1-Score           : {f1_score:.2f}%")
        print(f"• Report Logged To   : {run_file}")
        print("="*55 + "\n")

        return benchmark_report