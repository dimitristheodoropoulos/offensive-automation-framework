"""
Insurance Claims Triage CLI -- ίδιο ρόλο με cli.py του OSAF pentest pipeline,
αλλά για το insurance claims triage graph. Δέχεται claim data από JSON file
αντί για hardcoded sample.

Usage:
    python3 insurance_cli.py --claim examples/claims/auto_high_risk.json
    python3 insurance_cli.py --list-samples
"""
import argparse
import json
import os
import sys

from orchestration.insurance_state import new_insurance_state
from orchestration.insurance_graph import insurance_agent_app

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "examples", "claims")


def list_samples() -> None:
    if not os.path.isdir(SAMPLES_DIR):
        print(f"No samples directory found at {SAMPLES_DIR}")
        return
    print(f"Available sample claims in {SAMPLES_DIR}:")
    for fname in sorted(os.listdir(SAMPLES_DIR)):
        if fname.endswith(".json"):
            print(f"  - examples/claims/{fname}")


def load_claim(path: str) -> dict:
    if not os.path.isfile(path):
        print(f"[!] Claim file not found: {path}")
        sys.exit(1)
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON in {path}: {e}")
            sys.exit(1)


def run_claim(claim: dict) -> None:
    state = new_insurance_state(claim)
    final_state = insurance_agent_app.invoke(state)

    print("\n=== Reasoning Trail ===")
    for line in final_state["history"]:
        print(line)

    print("\n=== Final Report ===")
    print(final_state["report"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Insurance Claims Triage Agent CLI")
    parser.add_argument("--claim", type=str, help="Path to a claim JSON file to score")
    parser.add_argument("--list-samples", action="store_true", help="List available sample claim files")
    args = parser.parse_args()

    if args.list_samples:
        list_samples()
        return

    if not args.claim:
        print("No --claim path provided. Use --list-samples to see available examples, or pass --claim <path>.")
        sys.exit(1)

    claim = load_claim(args.claim)
    run_claim(claim)


if __name__ == "__main__":
    main()
