def lookup_cves(services):
    """Correlates detected services with a local vulnerability database map."""
    # Τοπική προσομοίωση CVE database για offline σταθερότητα
    vuln_db = {
        "ssh": ["CVE-2024-6387 (RegreSSHion)", "CVE-2023-38408"],
        "http": ["CVE-2021-41773 (Path Traversal)", "CVE-2022-22965"],
        "https": ["CVE-2020-0601"],
        "http-proxy": ["CVE-2022-22963"]
    }
    
    enriched_data = []
    for s in services:
        service_name = s["service"]
        cves = vuln_db.get(service_name, [])
        
        enriched_data.append({
            "port": s["port"],
            "service": service_name,
            "cves": cves,
            "severity": "Critical" if "2024" in str(cves) or "2021" in str(cves) else "Medium" if cves else "Info"
        })
        
    return enriched_data