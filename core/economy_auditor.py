# core/economy_auditor.py
import asyncio
import time
import httpx
from typing import Dict, Any

class InGameEconomyAuditor:
    def __init__(self, target_base_url: str = "http://127.0.0.1:3000"):
        self.target_base_url = target_base_url.rstrip("/")
        self.results = []

    async def test_race_condition_purchase(self, endpoint: str, payload: dict, headers: dict = None, concurrent_requests: int = 20) -> Dict[str, Any]:
        """
        Εκτελεί πολλαπλά parallel αιτήματα (concurrency attack) για τον εντοπισμό 
        Race Conditions σε in-game καταστήματα ή inventory actions.
        """
        url = f"{self.target_base_url}/{endpoint.lstrip('/')}"
        headers = headers or {"Content-Type": "application/json"}
        
        print(f"[*] [Economy Auditor] Launching {concurrent_requests} concurrent requests against: {url}")
        
        start_time = time.time()
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            tasks = [
                client.post(url, json=payload, headers=headers)
                for _ in range(concurrent_requests)
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.time() - start_time
        
        success_count = 0
        error_count = 0
        status_codes = {}
        response_bodies = []

        for resp in responses:
            if isinstance(resp, Exception):
                error_count += 1
            else:
                code = resp.status_code
                status_codes[code] = status_codes.get(code, 0) + 1
                if 200 <= code < 300:
                    success_count += 1
                    try:
                        response_bodies.append(resp.json())
                    except Exception:
                        response_bodies.append(resp.text)

        # Ανάλυση αποτελεσμάτων για πιθανό Race Condition (πολλαπλές επιτυχίες σε περιορισμένο πόρο)
        vulnerable = success_count > 1
        severity = "CRITICAL" if vulnerable else "LOW"

        audit_report = {
            "endpoint": endpoint,
            "concurrent_requests": concurrent_requests,
            "success_count": success_count,
            "error_count": error_count,
            "status_codes": status_codes,
            "vulnerable_to_race_condition": vulnerable,
            "severity": severity,
            "duration_seconds": round(duration, 3),
            "description": "Inventory Item Duplication / Race Condition detected via high-concurrency POST requests." if vulnerable else "Endpoint appears synchronized correctly."
        }

        self.results.append(audit_report)
        return audit_report

    def run_audit_sync(self, endpoint: str, payload: dict, concurrent_requests: int = 20) -> Dict[str, Any]:
        """Synchronous wrapper για εύκολη κλήση από τα υφιστάμενα agents/tools."""
        return asyncio.run(self.test_race_condition_purchase(endpoint, payload, concurrent_requests=concurrent_requests))