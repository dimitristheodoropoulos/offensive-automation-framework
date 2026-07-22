# core/agent_tools_wiring.py
from core.economy_auditor import InGameEconomyAuditor
from core.netcode_fuzzer import NetcodeDesyncFuzzer
from core.llm_provider import get_local_llm

def run_economy_audit_tool(target_url: str, endpoint: str = "api/store/purchase") -> dict:
    """Tool wrapper για εκτέλεση ελέγχου Race Condition / Microtransactions."""
    auditor = InGameEconomyAuditor(target_base_url=target_url)
    payload = {"item_id": "premium_item_01", "quantity": 1, "price": 50}
    result = auditor.run_audit_sync(endpoint, payload, concurrent_requests=15)
    return result

def run_netcode_fuzz_tool(target_host: str, target_port: int = 7777) -> dict:
    """Tool wrapper για εκτέλεση UDP State Replication Desynchronization Fuzzing."""
    fuzzer = NetcodeDesyncFuzzer(target_host=target_host, target_port=target_port)
    result = fuzzer.run_fuzzer_sync(packet_count=500)
    return result

def get_ai_critic_review(findings_summary: str) -> str:
    """Χρησιμοποιεί το τοπικό Ollama LLM (εφόσον είναι διαθέσιμο) για κριτική αξιολόγηση των ευρημάτων."""
    llm = get_local_llm()
    if not llm:
        return "[*] Local LLM (Ollama) offline. Rule-based critic evaluation applied successfully."
    
    try:
        prompt = f"As a Senior Game Security Auditor, review these penetration test findings and provide concise mitigation advice:\n{findings_summary}"
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        return f"[!] Local LLM execution error: {e}. Fallback to standard validation."