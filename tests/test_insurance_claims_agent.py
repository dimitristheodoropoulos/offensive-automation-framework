from orchestration.insurance_state import new_insurance_state
from orchestration.insurance_graph import insurance_agent_app

CLAIM_HIGH_RISK = {
    "claim_id": "CLM-100",
    "policy_id": "POL-1",
    "claim_amount": 9500.0,
    "claim_type": "auto",
    "policy_start_date": "2026-07-01",
    "claim_date": "2026-07-15",
    "submitted_docs": [],
    "historical_avg_claim_amount": 2000.0,
    "prior_claims_count": 6,
    "metadata": {},
}

CLAIM_LOW_RISK = {
    "claim_id": "CLM-101",
    "policy_id": "POL-2",
    "claim_amount": 500.0,
    "claim_type": "health",
    "policy_start_date": "2019-01-01",
    "claim_date": "2026-07-15",
    "submitted_docs": ["medical_report", "invoice"],
    "historical_avg_claim_amount": 550.0,
    "prior_claims_count": 0,
    "metadata": {},
}


def test_high_risk_claim_routes_to_human_review():
    state = new_insurance_state(CLAIM_HIGH_RISK)
    final_state = insurance_agent_app.invoke(state)
    assert final_state["risk_level"] == "high"
    assert final_state["requires_human_review"] is True
    assert "manual underwriter" in final_state["remediation"]


def test_low_risk_claim_auto_approved():
    state = new_insurance_state(CLAIM_LOW_RISK)
    final_state = insurance_agent_app.invoke(state)
    assert final_state["risk_level"] == "low"
    assert final_state["requires_human_review"] is False
    assert "auto-approved" in final_state["remediation"]


def test_missing_required_fields_ends_early():
    incomplete_claim = {"claim_id": "CLM-102"}
    state = new_insurance_state(incomplete_claim)
    final_state = insurance_agent_app.invoke(state)
    assert final_state["next_action"] == "end"
    assert final_state.get("report") is None


def test_llm_explainer_produces_summary_or_graceful_fallback():
    """
    Δεν κάνουμε mock το LLM call εδώ -- αν δεν υπάρχει GEMINI_API_KEY στο .env
    ή αποτύχει το call, το node πρέπει να πέσει graceful σε fallback string,
    όχι να ρίξει exception.
    """
    state = new_insurance_state(CLAIM_HIGH_RISK)
    final_state = insurance_agent_app.invoke(state)
    assert final_state.get("llm_summary") is not None
    assert isinstance(final_state["llm_summary"], str)
    assert len(final_state["llm_summary"]) > 0
