# tests/test_rag.py
from core.rag_store import CveRagStore

def test_rag_store_operations():
    # Χρησιμοποιούμε ξεχωριστό temporary directory για τα tests αν χρειάζεται
    rag = CveRagStore(persist_directory="./test_chroma_db")
    
    test_cve = [{
        "id": "CVE-2025-9999",
        "description": "Buffer overflow vulnerability in game asset loader parsing malicious files.",
        "severity": "HIGH",
        "cvss": 8.1
    }]
    
    rag.add_cves(test_cve)
    
    # Αναζήτηση με σημασιολογικά παρόμοια φράση
    results = rag.search_similar_cves("memory corruption and buffer overflow during asset loading")
    
    assert len(results) > 0
    assert results[0]["cve_id"] == "CVE-2025-9999"
    assert results[0]["severity"] == "HIGH"