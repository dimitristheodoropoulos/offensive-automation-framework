# scanner/mobile_analyzer.py
import re
import os
from typing import Dict, Any, List

class MobileAppAnalyzer:
    """
    Static Application Security Testing (SAST) Engine for Mobile Applications.
    Analyzes Android Manifests, APK resources, and Mobile Source Code.
    """

    CRITICAL_PERMISSIONS = [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION"
    ]

    HARDCODED_SECRET_PATTERNS = {
        "Google API Key": r"AIzaSy[A-Za-z0-9_-]{33}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Generic JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "Hardcoded Private Key": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"
    }

    def analyze_manifest_content(self, manifest_xml: str) -> List[Dict[str, Any]]:
        """Αναλύει το AndroidManifest.xml για επισφαλείς ρυθμίσεις."""
        findings = []

        # 1. Cleartext HTTP Traffic
        if 'android:usesCleartextTraffic="true"' in manifest_xml:
            findings.append({
                "name": "Mobile Cleartext HTTP Traffic Enabled",
                "risk": "High",
                "category": "Mobile Network Security",
                "description": "The Android application explicitly allows unencrypted HTTP communication.",
                "mitigation": "Set android:usesCleartextTraffic='false' in AndroidManifest.xml."
            })

        # 2. Debuggable Flag
        if 'android:debuggable="true"' in manifest_xml:
            findings.append({
                "name": "Mobile Application Marked Debuggable",
                "risk": "High",
                "category": "Mobile Runtime Security",
                "description": "App is compiled in debug mode, allowing runtime inspection and memory dumping.",
                "mitigation": "Set android:debuggable='false' before production release."
            })

        # 3. Critical Permissions
        for perm in self.CRITICAL_PERMISSIONS:
            if perm in manifest_xml:
                perm_name = perm.split(".")[-1]
                findings.append({
                    "name": f"Excessive Mobile Permission: {perm_name}",
                    "risk": "Medium",
                    "category": "Mobile Access Control",
                    "description": f"Application requests sensitive permission: {perm}",
                    "mitigation": "Enforce the principle of least privilege."
                })

        return findings

    def scan_source_for_secrets(self, file_content: str) -> List[Dict[str, Any]]:
        """Σαρώνει πηγαίο κώδικα/strings για hardcoded ευαίσθητα δεδομένα."""
        findings = []
        for secret_type, pattern in self.HARDCODED_SECRET_PATTERNS.items():
            if re.search(pattern, file_content):
                findings.append({
                    "name": f"Hardcoded Mobile Secret: {secret_type}",
                    "risk": "Critical",
                    "category": "Mobile Credential Exposure",
                    "description": f"Found embedded sensitive pattern matching {secret_type}.",
                    "mitigation": "Remove secrets from code; use Android Keystore / iOS Keychain."
                })
        return findings