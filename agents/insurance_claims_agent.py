from core.adapters import global_registry
from core.schemas import ToolExecutionResult


def run_insurance_claims_agent(state: dict) -> dict:
    """
    LangGraph node για claim fraud/risk scoring.
    Ίδιο pattern με agents/game_security_agent.py: adapter registry, όχι hardcoded λογική.
    """
    claim = state.get("claim", {})
    claim_id = claim.get("claim_id", "unknown_claim")
    state.setdefault("history", [])
    state.setdefault("fraud_signals", [])

    state["history"].append(f"[*] [Insurance Claims Agent] Scoring claim: {claim_id}")

    try:
        adapter = global_registry.get("insurance_claim_fraud_scorer")
        result: ToolExecutionResult = adapter.execute(target=claim_id, claim=claim)

        state["risk_score"] = result.raw_metadata.get("risk_score", 0.0)
        state["risk_level"] = result.raw_metadata.get("risk_level", "low")
        state["history"].append(
            f"[Insurance Claims Agent] Risk score: {state['risk_score']} ({state['risk_level']}) "
            f"| Signals: {result.raw_metadata.get('signals_count', 0)}"
        )

        for signal in result.vulnerabilities:
            state["fraud_signals"].append({
                "signal_id": signal.vuln_id,
                "title": signal.title,
                "severity": signal.severity,
                "description": signal.description,
                "remediation": signal.remediation,
            })

        state["requires_human_review"] = state["risk_level"] == "high"

    except Exception as e:
        state["history"].append(f"[!] Error executing insurance claim adapter: {str(e)}")
        state["risk_level"] = "medium"
        state["requires_human_review"] = True

    return state
