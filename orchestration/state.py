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


def new_state(target: str) -> PentestState:
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
    }