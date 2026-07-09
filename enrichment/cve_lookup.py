"""
CVE Lookup Module with RAG Support
Supports both Vector-based (Chroma) and Dictionary-based (fallback) lookups
"""

# Προσπάθεια να χρησιμοποιήσει RAG, αλλιώς fallback σε dictionary
try:
    import chromadb
    from sentence_transformers import SentenceTransformer
    
    class RAGCVELookup:
        def __init__(self):
            """Αρχικοποίηση Chroma vector store για CVE semantic search"""
            try:
                self.client = chromadb.Client()
                self.collection = self.client.get_or_create_collection(
                    name="cves",
                    metadata={"hnsw:space": "cosine"}
                )
                self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
                self._init_cve_database()
                self.rag_enabled = True
            except Exception as e:
                print(f"[!] RAG initialization failed: {e}. Falling back to dictionary lookup.")
                self.rag_enabled = False
        
        def _init_cve_database(self):
            """Γεμίζει τη βάση με γνωστά CVEs"""
            cves = [
                {"id": "CVE-2024-6387", "service": "ssh", "description": "RegreSSHion in OpenSSH"},
                {"id": "CVE-2023-38408", "service": "ssh", "description": "OpenSSH vulnerability"},
                {"id": "CVE-2021-41773", "service": "http", "description": "Apache Path Traversal"},
                {"id": "CVE-2022-22965", "service": "http", "description": "Spring Framework RCE"},
                {"id": "CVE-2020-0601", "service": "https", "description": "Windows CryptoAPI"},
                {"id": "CVE-2022-22963", "service": "http-proxy", "description": "Spring Cloud Function RCE"},
            ]
            
            for cve in cves:
                text = f"{cve['service']} {cve['description']}"
                embedding = self.embedder.encode(text)
                
                self.collection.add(
                    ids=[cve['id']],
                    embeddings=[embedding.tolist()],
                    documents=[text],
                    metadatas=[{"service": cve['service'], "cve_id": cve['id']}]
                )
        
        def lookup_cves(self, service_name: str, top_k: int = 3) -> list:
            """Κάνει similarity search για service και επιστρέφει top-k CVEs"""
            if not self.rag_enabled:
                return []
            
            try:
                query_embedding = self.embedder.encode(service_name)
                results = self.collection.query(
                    query_embeddings=[query_embedding.tolist()],
                    n_results=top_k
                )
                
                cves = []
                if results['ids'] and len(results['ids']) > 0:
                    for cve_id in results['ids'][0]:
                        cves.append(cve_id)
                
                return cves
            except Exception as e:
                print(f"[!] RAG lookup failed: {e}. Using fallback.")
                return []
    
    _rag_instance = RAGCVELookup()
    RAG_ENABLED = _rag_instance.rag_enabled
    
except ImportError:
    print("[!] Chromadb or sentence-transformers not installed. Using dictionary-based CVE lookup.")
    RAG_ENABLED = False
    _rag_instance = None


def lookup_cves(services):
    """
    Correlates detected services with CVE database.
    Uses RAG if available, falls back to dictionary lookup.
    """
    # Τοπική προσομοίωση CVE database (Fallback)
    vuln_db = {
        "ssh": ["CVE-2024-6387 (RegreSSHion)", "CVE-2023-38408"],
        "http": ["CVE-2021-41773 (Path Traversal)", "CVE-2022-22965"],
        "https": ["CVE-2020-0601"],
        "http-proxy": ["CVE-2022-22963"]
    }
    
    enriched_data = []
    
    for s in services:
        service_name = s["service"]
        
        # Προσπάθεια RAG lookup πρώτα
        if RAG_ENABLED and _rag_instance:
            cves = _rag_instance.lookup_cves(service_name, top_k=3)
        else:
            cves = []
        
        # Fallback σε dictionary αν RAG δεν έβγαλε αποτέλεσμα
        if not cves:
            cves = vuln_db.get(service_name, [])
        
        enriched_data.append({
            "port": s["port"],
            "service": service_name,
            "cves": cves,
            "severity": "Critical" if "2024" in str(cves) or "2021" in str(cves) else "Medium" if cves else "Info"
        })
    
    return enriched_data