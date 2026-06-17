import argparse
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.nmap_integration import run_nmap_scan
from enrichment.cve_lookup import lookup_cves
from post_exploitation.adversary_sim import simulate_post_exploitation
from reporting.json_export import export_to_json

def main():
    parser = argparse.ArgumentParser(description="OSAF v2.0: Tiger Team Edition")
    parser.add_argument("-t", "--target", required=True, help="Target IP for automated assessment")
    parser.add_argument("--sim-post", action="store_true", help="Trigger safe post-exploitation simulation")
    args = parser.parse_args()

    print("\n" + "🐅 " * 15)
    print(" OSAF v2.0: Offensive Security Automation Framework")
    print("🐅 " * 15 + "\n")

    # Step 1: Real Tool Integration (Nmap)
    services = run_nmap_scan(args.target)
    
    # Step 2: Intel Enrichment
    enriched_results = lookup_cves(services)

    # Step 3: Post-Exploitation Simulation (Optional Flag)
    post_exp_data = {}
    if args.sim_post or args.target == "127.0.0.1":
        post_exp_data = simulate_post_exploitation()

    # Step 4: Consolidation & Reporting
    final_report = {
        "target_host": args.target,
        "infrastructure_vulnerabilities": enriched_results,
        "post_exploitation_recon": post_exp_data
    }

    export_to_json(final_report)

if __name__ == "__main__":
    main()