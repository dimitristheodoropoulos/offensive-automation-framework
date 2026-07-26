from dotenv import load_dotenv
load_dotenv()

from langgraph.graph import StateGraph, END  # noqa: E402

from orchestration.insurance_state import InsuranceState  # noqa: E402
from agents.insurance_claims_agent import run_insurance_claims_agent  # noqa: E402
from core.adapters import global_registry  # noqa: E402
from adapters.insurance_claim_adapter import InsuranceClaimFraudAdapter  # noqa: E402

# Registration του adapter -- ίδιο μοτίβο με core/init_framework.py's initialize_osaf_tools()
try:
    global_registry.get("insurance_claim_fraud_scorer")
except KeyError:
    global_registry.register(InsuranceClaimFraudAdapter())


# ==========================================
# 1. INTAKE NODE
# ==========================================
def intake_agent_node(state: InsuranceState) -> InsuranceState:
    state["history"] = state.get("history", [])
    claim = state.get("claim", {})
    required_fields = ["claim_id", "policy_id", "claim_amount", "claim_type", "claim_date", "policy_start_date"]
    missing = [f for f in required_fields if not claim.get(f)]

    if missing:
        state["history"].append(f"[Intake Agent] Missing required claim fields: {missing}")
        state["next_action"] = "end"
    else:
        state["history"].append(f"[Intake Agent] Claim {claim['claim_id']} validated, routing to fraud scoring.")
        state["next_action"] = "score"

    return state


# ==========================================
# 2. FRAUD SCORING NODE (wraps agents/insurance_claims_agent.py)
# ==========================================
def fraud_scoring_agent_node(state: InsuranceState) -> InsuranceState:
    state = run_insurance_claims_agent(state)  # type: ignore[assignment]
    state["next_action"] = "critic_review"
    return state


# ==========================================
# 3. CRITIC-REFINEMENT NODE (ίδιο pattern με το OSAF critic_agent_node)
# ==========================================
def critic_agent_node(state: InsuranceState) -> InsuranceState:
    state["history"] = state.get("history", [])
    state["iteration_count"] = state.get("iteration_count", 0) + 1

    signals_count = len(state.get("fraud_signals", []))

    if signals_count == 0 and state["iteration_count"] < 2:
        # Δεν βρέθηκε κανένα σήμα -- ξαναρέχουμε το scoring σαν sanity-check,
        # ίδιο μοτίβο retry με το OSAF's critic_agent_node.
        state["critic_feedback"] = "No fraud signals detected -- re-running scoring pass."
        state["next_action"] = "retry_score"
    else:
        state["critic_feedback"] = "Scoring validated."
        state["next_action"] = "route_by_risk"

    state["history"].append(f"[Critic Agent] {state['critic_feedback']}")
    return state


# ==========================================
# 4a. HUMAN REVIEW NODE
# ==========================================
def human_review_node(state: InsuranceState) -> InsuranceState:
    state["history"] = state.get("history", [])
    state["remediation"] = "Claim flagged for manual underwriter review due to high risk score."
    state["history"].append("[Human Review] Claim escalated to manual review queue.")
    state["next_action"] = "generate_report"
    return state


# ==========================================
# 4b. AUTO APPROVAL NODE
# ==========================================
def auto_approval_node(state: InsuranceState) -> InsuranceState:
    state["history"] = state.get("history", [])
    state["remediation"] = "Claim auto-approved -- risk within acceptable threshold."
    state["history"].append("[Auto Approval] Claim approved automatically.")
    state["next_action"] = "generate_report"
    return state


# ==========================================
# 5. REPORT NODE
# ==========================================
def report_node(state: InsuranceState) -> InsuranceState:
    state["history"] = state.get("history", [])
    claim = state.get("claim", {})
    lines = [
        f"# Claim Risk Report -- {claim.get('claim_id', 'unknown')}",
        f"Risk score: {state.get('risk_score')} ({state.get('risk_level')})",
        f"Requires human review: {state.get('requires_human_review')}",
        f"Decision: {state.get('remediation')}",
        "",
        "## Fraud Signals",
    ]
    for s in state.get("fraud_signals", []):
        lines.append(f"- [{s['severity']}] {s['title']}: {s['description']}")

    state["report"] = "\n".join(lines)
    state["history"].append("[Report Agent] Claim risk report compiled.")
    state["next_action"] = "end"
    return state


# ==========================================
# ROUTER
# ==========================================
def insurance_router(state: InsuranceState) -> str:
    action = state["next_action"]
    if action == "score" or action == "retry_score":
        return "fraud_scoring_agent"
    elif action == "critic_review":
        return "critic_agent"
    elif action == "route_by_risk":
        return "human_review" if state.get("risk_level") == "high" else "auto_approval"
    elif action == "generate_report":
        return "report_node"
    return "end"


# ==========================================
# GRAPH COMPILATION
# ==========================================
insurance_workflow = StateGraph(InsuranceState)

insurance_workflow.add_node("intake_agent", intake_agent_node)
insurance_workflow.add_node("fraud_scoring_agent", fraud_scoring_agent_node)
insurance_workflow.add_node("critic_agent", critic_agent_node)
insurance_workflow.add_node("human_review", human_review_node)
insurance_workflow.add_node("auto_approval", auto_approval_node)
insurance_workflow.add_node("report_node", report_node)

insurance_workflow.set_entry_point("intake_agent")

insurance_workflow.add_conditional_edges(
    "intake_agent", insurance_router,
    {"fraud_scoring_agent": "fraud_scoring_agent", "end": END}
)
insurance_workflow.add_edge("fraud_scoring_agent", "critic_agent")
insurance_workflow.add_conditional_edges(
    "critic_agent", insurance_router,
    {
        "fraud_scoring_agent": "fraud_scoring_agent",
        "human_review": "human_review",
        "auto_approval": "auto_approval",
    }
)
insurance_workflow.add_edge("human_review", "report_node")
insurance_workflow.add_edge("auto_approval", "report_node")
insurance_workflow.add_edge("report_node", END)

insurance_agent_app = insurance_workflow.compile()
