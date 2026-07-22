from core.adapters import global_registry
from core.schemas import ToolExecutionResult

def run_game_security_agent(state: dict) -> dict:
    """
    LangGraph node for game security auditing, netcode fuzzing, and microtransaction checks.
    Uses the Tool Adapter pattern to decouple orchestration from execution.
    """
    target = state.get("target", "127.0.0.1")
    state.setdefault("logs", [])
    state.setdefault("vulnerabilities", [])

    state["logs"].append(f"[*] [Game Security Agent] Initializing audit on target: {target}")

    try:
        # Ανάκτηση του προσαρμογέα μέσω του Registry (π.χ. proprietary game fuzzer)
        adapter = global_registry.get("proprietary_game_fuzzer")
        
        # Εκτέλεση εργαλείου και λήψη τυποποιημένου Pydantic result
        result: ToolExecutionResult = adapter.execute(target=target)

        state["logs"].append(f"[*] [{result.tool_name}] Status: {result.status} | Metadata: {result.raw_metadata}")

        # Μετατροπή των ευρημάτων σε dict για αποθήκευση στο State
        for vuln in result.vulnerabilities:
            state["vulnerabilities"].append(vuln.model_dump())
            state["logs"].append(f"[!] Discovered: [{vuln.vuln_id}] {vn_title(vuln.title)} ({vuln.severity})")

    except Exception as e:
        state["logs"].append(f"[!] Error executing game security adapter: {str(e)}")

    return state

def vn_title(title: str) -> str:
    return title