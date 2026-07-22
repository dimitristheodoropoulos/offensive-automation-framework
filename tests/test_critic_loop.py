# tests/test_critic_loop.py
from orchestration.state import new_state
from orchestration.graph import critic_agent_node

def test_critic_agent_triggers_retry():
    """Ελέγχει ότι ο Critic ζητάει επανάληψη (retry) αν δεν βρεθούν ευρήματα στην 1η επανάληψη."""
    state = new_state("127.0.0.1")
    state["web_vulnerabilities"] = [] # Κανένα εύρημα
    state["iteration_count"] = 0
    
    updated_state = critic_agent_node(state)
    
    assert updated_state["iteration_count"] == 1
    assert updated_state["requires_remediation"] is True
    assert updated_state["next_action"] == "retry_web"
    assert "Zero vulnerabilities" in updated_state["critic_feedback"]


def test_critic_agent_approves_report():
    """Ελέγχει ότι ο Critic εγκρίνει τη ροή προς το game security stream αν υπάρχουν ευρήματα."""
    state = new_state("127.0.0.1")
    state["web_vulnerabilities"] = [{"name": "XSS", "risk": "Medium"}]
    state["iteration_count"] = 1
    
    updated_state = critic_agent_node(state)
    
    assert updated_state["requires_remediation"] is False
    assert updated_state["next_action"] == "game_security_stream"
    assert "Scan quality validated" in updated_state["critic_feedback"]