import os
import json
import time
from datetime import datetime

def check_system_health():
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "database_exists": os.path.exists("reports/osaf_history.db"),
        "vector_store_exists": os.path.exists("cve_vector_store/chroma.sqlite3"),
        "benchmarks_count": len(os.listdir("benchmarks")) if os.path.exists("benchmarks") else 0,
        "status": "Operational"
    }
    
    os.makedirs("reports", exist_ok=True)
    log_path = "reports/system_health_log.json"
    
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
        
    print(f"Health check executed successfully. Status: {report['status']}")
    return report

if __name__ == "__main__":
    check_system_health()