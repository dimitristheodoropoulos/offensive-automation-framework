# orchestration/benchmarker.py
import json

class AgentBenchmarker:
    def __init__(self, target_name, expected_vulns_count):
        self.target_name = target_name
        self.expected_vulns_count = expected_vulns_count # Ground Truth

    def evaluate_run(self, discovered_alerts, execution_time, tokens_used):
        # Φιλτράρισμα μοναδικών κρίσιμων ευρημάτων
        unique_vulns = len(set([alert['name'] for alert in discovered_alerts if alert.get('risk') in ['High', 'Medium']]))
        
        # Υπολογισμός μετρικών
        recall = (unique_vulns / self.expected_vulns_count) * 100 if self.expected_vulns_count > 0 else 0
        
        benchmark_report = {
            "Target": self.target_name,
            "Execution Time (s)": round(execution_time, 2),
            "LLM Tokens Expended": tokens_used,
            "Unique Medium/High Found": unique_vulns,
            "Expected Vulns": self.expected_vulns_count,
            "Recall Rate (%)": f"{round(recall, 2)}%"
        }
        
        with open(f"benchmarks/run_{self.target_name}.json", "w") as f:
            json.dump(benchmark_report, f, indent=4)
        
        print(f"[+] Benchmark report generated for {self.target_name}!")
        return benchmark_report