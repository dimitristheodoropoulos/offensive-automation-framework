# orchestration/insurance_state.py
from typing import TypedDict, List, Dict, Any, Optional


class ClaimRecord(TypedDict):
    claim_id: str
    policy_id: str
    claim_amount: float
    claim_type: str
    policy_start_date: str
    claim_date: str
    submitted_docs: List[str]
    historical_avg_claim_amount: float
    prior_claims_count: int
    metadata: Dict[str, Any]


class InsuranceState(TypedDict):
    claim: ClaimRecord
    fraud_signals: List[Dict[str, Any]]
    risk_score: float
    risk_level: str
    requires_human_review: bool
    llm_summary: Optional[str]
    next_action: str
    history: List[str]
    iteration_count: int
    critic_feedback: str
    remediation: Optional[str]
    report: Optional[str]


def new_insurance_state(claim: ClaimRecord) -> InsuranceState:
    return {
        "claim": claim,
        "fraud_signals": [],
        "risk_score": 0.0,
        "risk_level": "",
        "requires_human_review": False,
        "llm_summary": None,
        "next_action": "",
        "history": [],
        "iteration_count": 0,
        "critic_feedback": "",
        "remediation": None,
        "report": None,
    }
