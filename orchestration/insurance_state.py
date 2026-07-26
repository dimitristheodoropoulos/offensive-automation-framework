# orchestration/insurance_state.py
from typing import TypedDict, List, Dict, Any, Optional


class ClaimRecord(TypedDict):
    claim_id: str
    policy_id: str
    claim_amount: float
    claim_type: str                    # "auto" | "travel" | "health" | "property"
    policy_start_date: str             # ISO format "YYYY-MM-DD"
    claim_date: str                    # ISO format "YYYY-MM-DD"
    submitted_docs: List[str]
    historical_avg_claim_amount: float  # μέσος όρος claims αυτού του τύπου/πελάτη
    prior_claims_count: int
    metadata: Dict[str, Any]


class InsuranceState(TypedDict):
    claim: ClaimRecord
    fraud_signals: List[Dict[str, Any]]   # δομημένα ευρήματα (ίδιο σχήμα με PentestState's web_vulnerabilities)
    risk_score: float                      # 0-100
    risk_level: str                        # "low" | "medium" | "high"
    requires_human_review: bool
    next_action: str
    history: List[str]
    iteration_count: int
    critic_feedback: str
    remediation: Optional[str]
    report: Optional[str]


def new_insurance_state(claim: ClaimRecord) -> InsuranceState:
    """Helper για να ξεκινάς πάντα με ένα καθαρό, πλήρως αρχικοποιημένο state."""
    return {
        "claim": claim,
        "fraud_signals": [],
        "risk_score": 0.0,
        "risk_level": "",
        "requires_human_review": False,
        "next_action": "",
        "history": [],
        "iteration_count": 0,
        "critic_feedback": "",
        "remediation": None,
        "report": None,
    }
