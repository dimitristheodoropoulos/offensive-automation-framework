# orchestration/graph.py
from dotenv import load_dotenv
load_dotenv()  # Φορτώνει αυτόματα το .env αρχείο πριν από οποιαδήποτε αρχικοποίηση

import json  # noqa: E402
from langgraph.graph import StateGraph, END  # noqa: E402
from langchain_google_genai import ChatGoogleGenerativeAI  # noqa: E402

from orchestration.state import PentestState  # noqa: E402
from orchestration.tools import (  # noqa: E402
    nmap_tool, 
    cve_tool, 
    post_exploit_tool, 
    web_vuln_scanner_tool, 
    nuclei_tool,
    sqlmap_tool,
    proxy_logger_tool,
    websocket_fuzz_tool,
    netcode_fuzz_tool,
    microtransaction_audit_tool,
    report_generator_tool,
    remediation_tool
)
from orchestration.utils import extract_json_content, sanitize_untrusted_input  # noqa: E402

# --- ΕΙΣΑΓΩΓΗ ADAPTERS & REGISTRY ---
from core.adapters import global_registry  # noqa: E402
from core.init_framework import initialize_osaf_tools  # noqa: E402
from core.schemas import ToolExecutionResult  # noqa: E402

# Αρχικοποίηση των tool adapters κατα την εκκίνηση του γραφήματος
initialize_osaf_tools()

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash", 
    temperature=0.1,
    max_retries=6
)

# ==========================================
# 1. INFRASTRUCTURE & RECON AGENT NODE
# ==========================================
def infra_agent_node(state: PentestState) -> PentestState:
    state["history"] = state.get("history", [])
    print("[*] [Infra Agent] Scanning perimeter and analyzing network vectors...")
    
    state["scan_results"] = nmap_tool.invoke({"target_ip": state["target"]})
    state["enriched_cves"] = cve_tool.invoke({"services": state["scan_results"]})
    state["history"].append("[Infra Agent] Network scanning and CVE identification complete.")
    
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
    except Exception:
        state["next_action"] = "route_to_web"
        
    return state

# ==========================================
# 2. WEB APPLICATION AGENT NODE
# ==========================================
def web_agent_node(state: PentestState) -> PentestState:
    state["history"] = state.get("history", [])
    print("[*] [Web Agent] Initializing Web Application Security assessment pipeline...")
    
    target_url = f"http://{state['target']}:3000" if "127.0.0.1" in state["target"] else f"http://{state['target']}"
    
    proxy_status = proxy_logger_tool.invoke({"target_url": target_url})
    state["history"].append(f"[Web Agent] {proxy_status}")
    
    zap_alerts = web_vuln_scanner_tool.invoke({"target_url": target_url})
    state["web_vulnerabilities"] = zap_alerts
    state["web_scan_done"] = True
    state["history"].append(f"[Web Agent] ZAP Dynamic Scan completed. Discovered {len(zap_alerts)} core signatures.")

    print("[*] [Web Agent] Executing Nuclei vulnerability assessment templates...")
    nuclei_res = nuclei_tool.invoke({"target_url": target_url})
    state["history"].append("[Web Agent] Nuclei scan pipeline finalized.")
    
    if "Nuclei Findings:" in nuclei_res:
        state["web_vulnerabilities"].append({
            "name": "Nuclei Detected Vulnerabilities",
            "risk": "High/Medium",
            "url": target_url,
            "description": nuclei_res
        })

    sql_suspect = any(
        "sql" in str(alert.get("name")).lower() or 
        "injection" in str(alert.get("description")).lower() 
        for alert in zap_alerts
    )
    
    if sql_suspect or "3000" in target_url:
        state["history"].append("[Web Agent] High probability of injection vector detected. Delegating to SQLMap engine.")
        sqlmap_res = sqlmap_tool.invoke({"target_url": target_url})
        state["history"].append(f"[Web Agent] SQLMap assessment finalized: Vulnerable={sqlmap_res.get('vulnerable', False)}")
        
        if sqlmap_res.get("vulnerable"):
            state["web_vulnerabilities"].append({
                "name": f"Verified SQL Injection ({sqlmap_res.get('db_ms')})",
                "risk": "High",
                "url": target_url,
                "description": f"Parameter '{sqlmap_res.get('parameter')}' is highly vulnerable. Active Payload: {sqlmap_res.get('payload')}"
            })

    state["next_action"] = "critic_review"
    return state

# ==========================================
# 3. EXPLOITATION NODE
# ==========================================
def exploit_node(state: PentestState) -> PentestState:
    state["post_exploit_data"] = post_exploit_tool.invoke({})
    state["history"].append("[Exploit Agent] Privilege verification & system logging enumerated.")
    state["next_action"] = "route_to_web"
    return state

# ==========================================
# 4. CRITIC-REFINEMENT AGENT NODE
# ==========================================
def critic_agent_node(state: PentestState) -> PentestState:
    state["history"] = state.get("history", [])
    state["iteration_count"] = state.get("iteration_count", 0) + 1
    
    print(f"[*] [Critic Agent] Evaluating scan results (Iteration {state['iteration_count']})...")
    findings_count = len(state.get("web_vulnerabilities", []))
    
    if findings_count == 0 and state["iteration_count"] < 2:
        state["critic_feedback"] = "Zero vulnerabilities discovered. Re-running scan with adjusted depth."
        state["requires_remediation"] = True
        state["next_action"] = "retry_web"
    else:
        state["critic_feedback"] = "Scan quality validated. Proceeding to advanced Game Netcode & State analysis."
        state["requires_remediation"] = False
        state["next_action"] = "game_security_stream"
        
    state["history"].append(f"[Critic Agent] {state['critic_feedback']}")
    return state

# ==========================================
# 5. WEBSOCKET & ADVANCED GAME SECURITY AGENT NODE (Με Adapter Pattern)
# ==========================================
def game_security_agent_node(state: PentestState) -> PentestState:
    state["history"] = state.get("history", [])
    print("[*] [Game Security Agent] Initializing real-time game stream, netcode fuzzing & microtransaction audit...")
    
    target_host = state["target"]

    # 1. Εκτέλεση μέσω του Tool Adapter Registry (Proprietary Engine / Fuzzer Adapter)
    try:
        adapter = global_registry.get("proprietary_game_fuzzer")
        result: ToolExecutionResult = adapter.execute(target=target_host)
        
        state["history"].append(f"[*] [{result.tool_name}] Status: {result.status} | Metadata: {result.raw_metadata}")

        for vuln in result.vulnerabilities:
            state["web_vulnerabilities"].append({
                "name": f"Proprietary Engine: {vuln.title}",
                "risk": vuln.severity,
                "url": f"udp://{target_host}",
                "description": f"{vuln.description} Remediation: {vuln.remediation}"
            })
    except Exception as e:
        state["history"].append(f"[!] Warning: Proprietary adapter execution skipped: {str(e)}")

    # 2. WebSocket Fuzzing
    target_ws_url = f"ws://{target_host}:8080/ws" if "127.0.0.1" in target_host else f"ws://{target_host}/ws"
    ws_res = websocket_fuzz_tool.invoke({"target_url": target_ws_url})
    for finding in ws_res.get("findings", []):
        state["web_vulnerabilities"].append({
            "name": f"Game WS: {finding['vector']}",
            "risk": finding['severity'],
            "url": target_ws_url,
            "description": finding['details']
        })

    # 3. Netcode Fuzzing (UDP/TCP State Replication)
    netcode_res = netcode_fuzz_tool.invoke({"target_host": target_host, "port": 7777})
    if isinstance(netcode_res, dict) and "findings" in netcode_res:
        for finding in netcode_res.get("findings", []):
            state["web_vulnerabilities"].append({
                "name": f"Netcode Fuzzing: {finding.get('vector', 'State Replication')}",
                "risk": finding.get('severity', 'Medium'),
                "url": f"udp://{target_host}:7777",
                "description": finding.get('details', 'Netcode anomaly detected.')
            })

    # 4. Microtransaction & Matchmaking Logic Audit
    base_api_url = f"http://{target_host}:3000" if "127.0.0.1" in target_host else f"http://{target_host}"
    micro_res = microtransaction_audit_tool.invoke({"base_url": base_api_url})
    for vuln in micro_res.get("vulnerabilities", []):
        state["web_vulnerabilities"].append({
            "name": vuln.get("name"),
            "risk": vuln.get("risk"),
            "url": vuln.get("endpoint", base_api_url),
            "description": vuln.get("description")
        })

    state["history"].append("[Game Security Agent] Comprehensive game netcode, WS, and microtransaction audit completed.")
    state["next_action"] = "remediate"
    return state

# ==========================================
# 6. REMEDIATION AGENT NODE
# ==========================================
def remediation_agent_node(state: PentestState) -> PentestState:
    state["history"] = state.get("history", [])
    print("[*] [Remediation Agent] Generating secure code patches & mitigation strategies...")
    
    all_vulns = state.get("web_vulnerabilities", [])
    remediation_advice = remediation_tool.invoke({"vulnerabilities": all_vulns})
    
    state["web_vulnerabilities"].append({
        "name": "AI Remediation & Code Patches",
        "risk": "Info",
        "url": state.get("target"),
        "description": remediation_advice
    })
    
    state["history"].append("[Remediation Agent] Security patches and remediation advice compiled.")
    state["next_action"] = "generate_report"
    return state

# ==========================================
# 7. REPORT GENERATOR NODE
# ==========================================
def report_node(state: PentestState) -> PentestState:
    state["history"] = state.get("history", [])
    print("[*] [Report Agent] Compiling final security assessment report with remediation patches...")
    
    all_vulns = state.get("web_vulnerabilities", [])
    target = state.get("target", "unknown_target")
    
    report_status = report_generator_tool.invoke({
        "vulnerabilities": all_vulns, 
        "target": target
    })
    
    state["history"].append(f"[Report Agent] {report_status}")
    state["next_action"] = "end"
    return state

# ==========================================
# CONDITIONAL ROUTER LOGIC
# ==========================================
def multi_agent_router(state: PentestState) -> str:
    action = state["next_action"]
    if action == "exploit":
        return "exploit_node"
    elif action == "route_to_web" or action == "retry_web":
        return "web_agent_node"
    elif action == "game_security_stream":
        return "game_security_agent"
    elif action == "remediate":
        return "remediation_agent"
    elif action == "generate_report":
        return "report_node"
    return "end"

# ==========================================
# MULTI-AGENT WORKFLOW COMPILATION
# ==========================================
workflow = StateGraph(PentestState)

workflow.add_node("infra_agent", infra_agent_node)
workflow.add_node("exploit_node", exploit_node)
workflow.add_node("web_agent", web_agent_node)
workflow.add_node("critic_agent", critic_agent_node)
workflow.add_node("game_security_agent", game_security_agent_node)
workflow.add_node("remediation_agent", remediation_agent_node)
workflow.add_node("report_node", report_node)

workflow.set_entry_point("infra_agent")

workflow.add_conditional_edges(
    "infra_agent",
    multi_agent_router,
    {
        "exploit_node": "exploit_node",
        "web_agent_node": "web_agent",
        "end": END
    }
)

workflow.add_conditional_edges(
    "exploit_node",
    multi_agent_router,
    {
        "web_agent_node": "web_agent",
        "end": END
    }
)

workflow.add_edge("web_agent", "critic_agent")

workflow.add_conditional_edges(
    "critic_agent",
    multi_agent_router,
    {
        "web_agent_node": "web_agent",
        "game_security_agent": "game_security_agent",
        "end": END
    }
)

workflow.add_edge("game_security_agent", "remediation_agent")
workflow.add_edge("remediation_agent", "report_node")
workflow.add_edge("report_node", END)

agent_app = workflow.compile()