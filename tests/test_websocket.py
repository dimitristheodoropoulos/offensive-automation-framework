# tests/test_websocket.py
from orchestration.graph import game_security_agent_node
from orchestration.state import PentestState

def new_state(target: str) -> PentestState:
    return {
        "target": target,
        "history": [],
        "scan_results": [],
        "enriched_cves": [],
        "post_exploit_data": {},
        "web_vulnerabilities": [],
        "web_scan_done": False,
        "critic_feedback": "",
        "requires_remediation": False,
        "iteration_count": 0,
        "next_action": ""
    }

def test_websocket_agent_node_integration():
    """Ελέγχει ότι ο Game Security Agent (WebSocket & Netcode Fuzzer) ενσωματώνει τα ευρήματα στο state και κατευθύνει στο remediation."""
    state = new_state("127.0.0.1")
    updated_state = game_security_agent_node(state)
    
    # Ελέγχουμε ότι η επόμενη ενέργεια οδηγεί στο remediation
    assert updated_state["next_action"] == "remediate"
    assert isinstance(updated_state.get("web_vulnerabilities"), list)
    # Επαληθεύουμε ότι προστέθηκαν ευρήματα (από τα tools και τον adapter)
    assert len(updated_state.get("web_vulnerabilities")) > 0