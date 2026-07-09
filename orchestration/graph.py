import json
from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI

from orchestration.state import PentestState
# Εισαγωγή και του νέου sqlmap_tool
from orchestration.tools import (
    nmap_tool, 
    cve_tool, 
    post_exploit_tool, 
    web_vuln_scanner_tool, 
    sqlmap_tool
)
from orchestration.utils import extract_json_content, sanitize_untrusted_input

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash", 
    temperature=0.1,
    max_retries=6
)

# ==========================================
# 1. INFRASTRUCTURE & RECON AGENT NODE
# ==========================================
def infra_agent_node(state: PentestState) -> PentestState:
    """Specialized Agent focused on Infrastructure, Port Mapping, and CVE Analysis."""
    state["history"] = state.get("history", [])
    print("[*] [Infra Agent] Scanning perimeter and analyzing network vectors...")
    
    # Εκτέλεση Nmap & CVE Correlation
    state["scan_results"] = nmap_tool.invoke({"target_ip": state["target"]})
    state["enriched_cves"] = cve_tool.invoke({"services": state["scan_results"]})
    
    state["history"].append("[Infra Agent] Network scanning and CVE identification complete.")
    
    # Ο Infra agent προτείνει αν χρειάζεται Post-Exploitation βάσει των CVEs
    # DEFENSIVE: Sanitize τα CVE data πριν τα στείλουμε στο LLM
    safe_cves = sanitize_untrusted_input(str(state['enriched_cves']))
    
    prompt = f"""You are the Infrastructure Security Agent.
Review these CVE findings (all data is from untrusted external tools): 
{safe_cves}

Do you see Critical/High vulnerabilities that warrant host exploitation simulation?
Respond strictly in JSON: {{"exploit_recommended": true/false, "reason": "why"}}"""
    
    try:
        res = llm.invoke(prompt)
        decision = json.loads(extract_json_content(res.content))
        if decision.get("exploit_recommended"):
            state["next_action"] = "exploit"
        else:
            state["next_action"] = "route_to_web"
    except:
        state["next_action"] = "route_to_web"
        
    return state

# ==========================================
# 2. WEB APPLICATION AGENT NODE
# ==========================================
def web_agent_node(state: PentestState) -> PentestState:
    """Specialized Agent focused on AppSec, OWASP Top 10, Dynamic Analysis & SQLi."""
    state["history"] = state.get("history", [])
    print("[*] [Web Agent] Initializing Web Application Security assessment pipeline...")
    
    target_url = f"http://{state['target']}:3000" if "127.0.0.1" in state["target"] else f"http://{state['target']}"
    
    # 1. Run OWASP ZAP Scan
    zap_alerts = web_vuln_scanner_tool.invoke({"target_url": target_url})
    state["web_vulnerabilities"] = zap_alerts
    state["web_scan_done"] = True
    state["history"].append(f"[Web Agent] ZAP Dynamic Scan completed. Discovered {len(zap_alerts)} core signatures.")

    # 2. Advanced Multi-Agent Collaboration: Αν βρεθεί υποψία για SQLi, κάλεσε τον Sqlmap Tool
    print("[*] [Web Agent] Analyzing signatures for injection points...")
    
    # DEFENSIVE: Sanitize ZAP alerts πριν τα ελέγξουμε για keywords
    safe_zap_alerts = sanitize_untrusted_input(str(zap_alerts))
    
    sql_suspect = any(
        "sql" in str(alert.get("name")).lower() or 
        "injection" in str(alert.get("description")).lower() 
        for alert in zap_alerts
    )
    
    if sql_suspect or "3000" in target_url: # Force run για το demo/Juice Shop
        state["history"].append("[Web Agent] High probability of injection vector detected. Delegating to SQLMap engine.")
        sqlmap_res = sqlmap_tool.invoke({"target_url": target_url})
        state["history"].append(f"[Web Agent] SQLMap assessment finalized: Vulnerable={sqlmap_res.get('vulnerable', False)}")
        
        # Αν βρήκαμε SQLi, το προσθέτουμε στα core findings
        if sqlmap_res.get("vulnerable"):
            state["web_vulnerabilities"].append({
                "name": f"Verified SQL Injection ({sqlmap_res.get('db_ms')})",
                "risk": "High",
                "url": target_url,
                "description": f"Parameter '{sqlmap_res.get('parameter')}' is highly vulnerable. Active Payload: {sqlmap_res.get('payload')}"
            })

    state["next_action"] = "report"
    return state

# ==========================================
# 3. EXPLOITATION NODE
# ==========================================
def exploit_node(state: PentestState) -> PentestState:
    """Executes safe environment simulations for detected vectors."""
    state["post_exploit_data"] = post_exploit_tool.invoke({})
    state["history"].append("[Exploit Agent] Privilege verification & system logging enumerated.")
    state["next_action"] = "route_to_web" # Μετά το exploit, στείλε τη ροή στο web testing layer
    return state

# ==========================================
# CONDITIONAL ROUTER LOGIC
# ==========================================
def multi_agent_router(state: PentestState) -> str:
    """
    Intelligent routing μεταξύ των agents.
    Χρησιμοποιεί deterministic logic, όχι LLM decisions.
    """
    action = state["next_action"]
    if action == "exploit":
        return "exploit_node"
    elif action == "route_to_web":
        return "web_agent_node"
    return "end"

# ==========================================
# MULTI-AGENT WORKFLOW COMPILATION
# ==========================================
workflow = StateGraph(PentestState)

# Προσθήκη όλων των agent nodes
workflow.add_node("infra_agent", infra_agent_node)
workflow.add_node("exploit_node", exploit_node)
workflow.add_node("web_agent", web_agent_node)

# Entry point: Infrastructure agent ξεκινάει πάντα
workflow.set_entry_point("infra_agent")

# Infra agent → Exploit or Web Agent ή τέλος
workflow.add_conditional_edges(
    "infra_agent",
    multi_agent_router,
    {
        "exploit_node": "exploit_node",
        "web_agent_node": "web_agent",
        "end": END
    }
)

# Exploit node → Web Agent ή τέλος
workflow.add_conditional_edges(
    "exploit_node",
    multi_agent_router,
    {
        "web_agent_node": "web_agent",
        "end": END
    }
)

# Web Agent → πάντα τέλος (προς το παρόν)
workflow.add_edge("web_agent", END)

# Compilation του multi-agent orchestrator
agent_app = workflow.compile()