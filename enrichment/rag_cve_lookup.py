from chromadb.config import Settings
import chromadb
from sentence_transformers import SentenceTransformer

class RAGCVELookup:
    def __init__(self):
        # Αρχικοποίηση vector store
        self.client = chromadb.Client(Settings(
            chroma_db_impl="duckdb",
            persist_directory="./cve_vector_store",
            anonymized_telemetry=False
        ))
        
        self.collection = self.client.get_or_create_collection(
            name="cves",
            metadata={"hnsw:space": "cosine"}
        )
        
        self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
        
        # Populate με τα CVEs που ήδη έχεις
        self._init_cve_database()
    
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
    
    def lookup_cves_rag(self, service_name: str, top_k: int = 3) -> list:
        """Κάνει similarity search για service και επιστρέφει top-k CVEs"""
        query_embedding = self.embedder.encode(service_name)
        
        results = self.collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=top_k
        )
        
        cves = []
        if results['ids'] and len(results['ids']) > 0:
            for cve_id, metadata in zip(results['ids'][0], results['metadatas'][0]):
                cves.append(cve_id)
        
        return cves

# Global instance
rag_lookup = RAGCVELookup()

def lookup_cves_enhanced(services: list) -> list:
    """Enhanced version με RAG lookup"""
    enriched_data = []
    
    for service in services:
        service_name = service['service']
        
        # RAG lookup αντί για dictionary lookup
        cves = rag_lookup.lookup_cves_rag(service_name, top_k=5)
        
        enriched_data.append({
            "port": service["port"],
            "service": service_name,
            "cves": cves,
            "severity": "Critical" if "2024" in str(cves) or "2021" in str(cves) else "Medium" if cves else "Info"
        })
    
    return enriched_data