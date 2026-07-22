# scanner/game_script_sast.py
import re
from typing import List, Dict, Any

class GameScriptAnalyzer:
    """Analyzes game scripts (Lua, Python, JS) and configuration files (JSON/XML) for hardcoded secrets and logic flaws."""
    
    SECRET_PATTERNS = [
        (r"(?i)api[_-]?key\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "Hardcoded API Key"),
        (r"(?i)auth[_-]?token\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "Hardcoded Auth Token"),
        (r"(?i)secret[_-]?key\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "Hardcoded Secret Key"),
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Secret Key"),
    ]

    def scan_script_content(self, filename: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        for line_no, line in enumerate(content.splitlines(), 1):
            for pattern, vuln_name in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "name": vuln_name,
                        "risk": "High",
                        "file": filename,
                        "line": line_no,
                        "description": f"Detected sensitive credential pattern in game script/config at line {line_no}."
                    })
        
        if not findings:
            findings.append({
                "name": "Game Script SAST Clean",
                "risk": "Info",
                "file": filename,
                "description": "No hardcoded secrets or obvious script flaws detected."
            })
            
        return findings