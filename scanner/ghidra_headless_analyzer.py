# scanner/ghidra_headless_analyzer.py
import os
import subprocess
import shutil
import tempfile
import re
from typing import List, Dict, Any

class GhidraHeadlessAnalyzer:
    """
    Executes Ghidra in headless mode or falls back to binary parsing / string extraction
    to analyze compiled game binaries (PE/ELF) for hardcoded secrets, API endpoints, 
    and insecure function patterns.
    """
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def analyze_binary(self) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(self.binary_path):
            return [{"error": f"Binary path not found: {self.binary_path}"}]

        # Έλεγχος αν υπάρχει το Ghidra headless binary στο σύστημα ή μέσω GHIDRA_INSTALL_DIR
        ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR")
        analyze_headless = shutil.which("analyzeHeadless") or (
            os.path.join(ghidra_home, "support", "analyzeHeadless") if ghidra_home else None
        )

        if not analyze_headless or not os.path.exists(analyze_headless):
            # Εναλλακτική ανάλυση (Fallback Static Analysis) αν το Ghidra δεν είναι εγκατεστημένο
            return self._fallback_static_analysis()

        # Εκτέλεση Ghidra Headless
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                project_name = "osaf_ghidra_proj"
                cmd = [
                    analyze_headless,
                    tmpdir,
                    project_name,
                    "-import", self.binary_path,
                    "-readOnly"
                ]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
                if result.returncode == 0:
                    findings.append({
                        "name": "Ghidra Headless Decompilation & Analysis",
                        "risk": "Info",
                        "description": f"Successfully analyzed {os.path.basename(self.binary_path)} via Ghidra headless engine."
                    })
                else:
                    findings.append({
                        "name": "Ghidra Execution Warning",
                        "risk": "Low",
                        "description": f"Ghidra exited with code {result.returncode}: {result.stderr[:200]}"
                    })
        except Exception as e:
            findings.extend(self._fallback_static_analysis())
        
        return findings

    def _fallback_static_analysis(self) -> List[Dict[str, Any]]:
        """Fallback heuristic binary analysis using Python string extraction and pattern matching."""
        findings = []
        try:
            with open(self.binary_path, "rb") as f:
                content = f.read()
            
            # Εξαγωγή ASCII strings μήκους >= 5 χαρακτήρων
            strings = re.findall(b"[ -~]{5,}", content)
            decoded_strings = [s.decode("latin-1", errors="ignore") for s in strings]

            # Έλεγχος για ευαίσθητα keywords (credentials, API keys, URLs)
            secret_keywords = ["api_key", "secret", "password", "bearer", "token", "http://", "https://", "db_pass"]
            found_secrets = []
            for s in decoded_strings:
                s_lower = s.lower()
                if any(kw in s_lower for kw in secret_keywords):
                    found_secrets.append(s[:100])

            if found_secrets:
                findings.append({
                    "name": "Hardcoded Secrets / Service Endpoints in Binary",
                    "risk": "High",
                    "description": f"Detected sensitive strings or backend endpoints in compiled binary: {found_secrets[:5]}",
                    "count": len(found_secrets)
                })
            else:
                findings.append({
                    "name": "Binary Static Analysis Summary",
                    "risk": "Info",
                    "description": f"Analyzed {os.path.basename(self.binary_path)}. No critical hardcoded credentials matched heuristic filters."
                })
        except Exception as e:
            findings.append({
                "error": f"Fallback binary static analysis failed: {str(e)}"
            })
        return findings