from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from orchestration.insurance_graph import insurance_agent_app
from orchestration.insurance_state import new_insurance_state

app = FastAPI(
    title="OSAF Insurtech & Security AI Agent API",
    description="Cloud-ready microservice wrapper for multi-agent insurance triage and security automation.",
    version="1.0.0",
)


class ClaimValidationRequest(BaseModel):
    claim_id: str
    policy_id: str
    claim_amount: float
    claim_type: str
    claim_date: str
    policy_start_date: str
    submitted_docs: List[str] = Field(default_factory=list)
    historical_avg_claim_amount: float = 0.0
    prior_claims_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "OSAF Agentic Cloud API",
        "graph_loaded": insurance_agent_app is not None,
    }


@app.post("/api/v1/insurance/triage")
def triage_claim(claim: ClaimValidationRequest):
    if insurance_agent_app is None:
        raise HTTPException(status_code=503, detail="Insurance multi-agent graph is not initialized.")
    try:
        initial_state = new_insurance_state(claim.model_dump())
        final_state = insurance_agent_app.invoke(initial_state)

        return {
            "claim_id": claim.claim_id,
            "risk_score": final_state.get("risk_score"),
            "risk_level": final_state.get("risk_level"),
            "llm_summary": final_state.get("llm_summary"),
            "fraud_signals": final_state.get("fraud_signals", []),
            "status": "success",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {str(e)}")
