import os
from typing import List, Dict, Any

# Dictionary Fallback αν αποτύχει το RAG / Vector DB
FALLBACK_VULN_DB = {
    "ssh": ["CVE-2024-6387 (RegreSSHion)", "CVE-2023-38408"],
    "http": ["CVE-2021-41773 (Path Traversal)", "CVE-2022-22965 (Spring4Shell)"],
    "https": ["CVE-2020-0601 (Windows CryptoAPI)"],
    "http-proxy": ["CVE-2022-22963 (Spring Cloud RCE)"]
}

try:
    import chromadb
    from sentence_transformers import SentenceTransformer

    class RAGCVELookup:
        def __init__(self, db_path: str = "./cve_vector_store"):
            self.db_path = db_path
            try:
                # Σύγχρονο ChromaDB Persistent Client API
                self.client = chromadb.PersistentClient(path=self.db_path)
                self.collection = self.client.get_or_create_collection(
                    name="cves",
                    metadata={"hnsw:space": "cosine"}
                )
                self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
                self._init_cve_database()
                self.rag_enabled = True
            except Exception as e:
                print(f"[!] [RAG CVE] Vector Store init failed: {e}. Falling back to dictionary lookup.")
                self.rag_enabled = False

        def _init_cve_database(self):
            """Πληρώνει τη βάση μόνο αν είναι άδεια (αποφυγή duplicates)"""
            if self.collection.count() > 0:
                return

            print("[*] [RAG CVE] Population of initial CVE Vector Database...")
            cves = [
                {"id": "CVE-2024-6387", "service": "ssh", "description": "RegreSSHion in OpenSSH Remote Code Execution"},
                {"id": "CVE-2023-38408", "service": "ssh", "description": "OpenSSH PKCS11 provider vulnerability"},
                {"id": "CVE-2021-41773", "service": "http", "description": "Apache Path Traversal and RCE"},
                {"id": "CVE-2022-22965", "service": "http", "description": "Spring4Shell Spring Framework RCE"},
                {"id": "CVE-2020-0601", "service": "https", "description": "Windows CryptoAPI Spoofing"},
                {"id": "CVE-2022-22963", "service": "http-proxy", "description": "Spring Cloud Function RCE"},
            ]

            ids, embeddings, documents, metadatas = [], [], [], []
            for cve in cves:
                text = f"{cve['service']} {cve['description']}"
                emb = self.embedder.encode(text).tolist()
                
                ids.append(cve["id"])
                embeddings.append(emb)
                documents.append(text)
                metadatas.append({"service": cve["service"], "cve_id": cve["id"]})

            self.collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas
            )
            print("[+] [RAG CVE] CVE Vector Database initialized successfully.")

        def lookup_cves(self, service_name: str, top_k: int = 3) -> List[str]:
            """Semantic similarity search για το δοσμένο service"""
            if not self.rag_enabled:
                return []

            try:
                query_emb = self.embedder.encode(service_name).tolist()
                results = self.collection.query(
                    query_embeddings=[query_emb],
                    n_results=top_k
                )

                if results and results.get("ids") and len(results["ids"]) > 0:
                    return results["ids"][0]
                return []
            except Exception as e:
                print(f"[!] [RAG CVE] Lookup failed: {e}")
                return []

    _rag_instance = RAGCVELookup()
    RAG_ENABLED = _rag_instance.rag_enabled

except ImportError:
    print("[!] [RAG CVE] Chromadb or sentence-transformers not found. Operating on Dictionary Fallback.")
    RAG_ENABLED = False
    _rag_instance = None


def lookup_cves(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Κύριο σημείο εισόδου (Entry Point) που καλείται από το cve_tool.
    Δέχεται τη λίστα των services από το Nmap scan και επιστρέφει εμπλουτισμένα CVEs.
    """
    enriched_data = []

    for s in services:
        service_name = str(s.get("service", "")).lower()
        port = s.get("port", "N/A")

        cves = []
        if RAG_ENABLED and _rag_instance:
            cves = _rag_instance.lookup_cves(service_name, top_k=3)

        # Fallback σε dictionary αν το RAG δεν επέστρεψε αποτελέσματα
        if not cves:
            cves = FALLBACK_VULN_DB.get(service_name, [])

        severity = "Critical" if any("2024" in str(c) or "2021" in str(c) for c in cves) else "Medium" if cves else "Info"

        enriched_data.append({
            "port": port,
            "service": service_name,
            "cves": cves,
            "severity": severity
        })

    return enriched_data