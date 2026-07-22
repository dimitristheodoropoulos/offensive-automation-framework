# tests/test_economy_auditor.py
import pytest
from core.economy_auditor import InGameEconomyAuditor

def test_economy_auditor_initialization():
    auditor = InGameEconomyAuditor(target_base_url="http://127.0.0.1:3000")
    assert auditor.target_base_url == "http://127.0.0.1:3000"
    assert isinstance(auditor.results, list)

def test_economy_auditor_structure():
    auditor = InGameEconomyAuditor()
    # Mocking/Testing δομή με τοπικό endpoint που πιθανώς δεν τρέχει (θα επιστρέψει error/exception χωρίς να κρασάρει)
    result = auditor.run_audit_sync("api/store/purchase", {"item_id": "sword_01", "price": 100}, concurrent_requests=5)
    
    assert "endpoint" in result
    assert "success_count" in result
    assert "vulnerable_to_race_condition" in result
    assert "severity" in result