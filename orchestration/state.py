# orchestration/state.py
from typing import TypedDict, List, Dict, Any


class PentestState(TypedDict):
    target: str
    scan_results: List[Dict[str, Any]]       # Output του nmap_integration.py
    enriched_cves: List[Dict[str, Any]]      # Output του cve_lookup.py
    web_vulnerabilities: List[Dict[str, Any]]  # Output του ZAP scan
    post_exploit_data: Dict[str, Any]        # Output του adversary_sim.py
    next_action: str                          # Απόφαση του Agent
    history: List[str]                        # Reasoning trace
    web_scan_done: bool                       # Αποφεύγει ατέρμον web_scan loop
    # Νέα πεδία για το Critic-Refinement Loop
    iteration_count: int
    critic_feedback: str
    requires_remediation: bool
    # Προαιρετικά πεδία για το Mobile SAST (companion app manifest/source)
    mobile_manifest: str
    mobile_source: str


def new_state(target: str, mobile_manifest: str = "", mobile_source: str = "") -> PentestState:
    """Helper για να ξεκινάς πάντα με ένα καθαρό, πλήρως αρχικοποιημένο state."""
    return {
        "target": target,
        "scan_results": [],
        "enriched_cves": [],
        "web_vulnerabilities": [],
        "post_exploit_data": {},
        "next_action": "",
        "history": [],
        "web_scan_done": False,
        "iteration_count": 0,
        "critic_feedback": "",
        "requires_remediation": False,
        "mobile_manifest": mobile_manifest,
        "mobile_source": mobile_source,
    }