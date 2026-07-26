"""
Standalone entrypoint για το Insurance Claims Triage agentic pipeline.
Ίδιο ρόλο με main_agentic.py, αλλά για το insurance domain.

Usage:
    python3 main_insurance.py
"""
from orchestration.insurance_state import new_insurance_state
from orchestration.insurance_graph import insurance_agent_app

SAMPLE_CLAIM = {
    "claim_id": "CLM-1001",
    "policy_id": "POL-5567",
    "claim_amount": 8500.0,
    "claim_type": "auto",
    "policy_start_date": "2026-07-10",
    "claim_date": "2026-07-20",
    "submitted_docs": ["police_report"],
    "historical_avg_claim_amount": 2200.0,
    "prior_claims_count": 4,
    "metadata": {},
}

if __name__ == "__main__":
    state = new_insurance_state(SAMPLE_CLAIM)
    final_state = insurance_agent_app.invoke(state)

    print("\n=== Reasoning Trail ===")
    for line in final_state["history"]:
        print(line)

    print("\n=== Final Report ===")
    print(final_state["report"])
