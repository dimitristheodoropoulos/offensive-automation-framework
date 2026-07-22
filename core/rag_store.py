# core/rag_store.py
import chromadb
from sentence_transformers import SentenceTransformer

class CveRagStore:
    def __init__(self, persist_directory: str = "./chroma_db"):
        """Αρχικοποίηση του ChromaDB client και του embedding model."""
        self.persist_directory = persist_directory
        self.client = chromadb.PersistentClient(path=self.persist_directory)
        
        # Χρησιμοποιούμε ένα ελαφρύ και γρήγορο μοντέλο για local embeddings
        print("[*] Loading SentenceTransformer model for CVE RAG...")
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
        
        # Δημιουργία ή φόρτωση της συλλογής CVEs
        self.collection = self.client.get_or_create_collection(name="cve_knowledge_base")

    def add_cves(self, cve_list: list):
        """Προσθήκη ή ενημέρωση CVEs στη βάση δεδομένων με τα embeddings τους."""
        if not cve_list:
            return

        documents = []
        metadatas = []
        ids = []

        for cve in cve_list:
            cve_id = cve.get("id", f"CVE-UNKNOWN-{hash(cve.get('description', ''))}")
            description = cve.get("description", "")
            severity = str(cve.get("severity", "MEDIUM"))
            cvss = float(cve.get("cvss", 5.0))

            documents.append(description)
            metadatas.append({"severity": severity, "cvss": cvss, "cve_id": cve_id})
            ids.append(str(cve_id))

        # Υπολογισμός embeddings
        embeddings = self.encoder.encode(documents).tolist()

        # Αποθήκευση στη ChromaDB
        self.collection.upsert(
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
            ids=ids
        )
        print(f"[+] Successfully indexed {len(documents)} CVEs into ChromaDB.")

    def search_similar_cves(self, query: str, n_results: int = 3) -> list:
        """Σημασιολογική αναζήτηση παρόμοιων CVEs βάσει περιγραφής ευρήματος."""
        if self.collection.count() == 0:
            return []

        query_embedding = self.encoder.encode([query]).tolist()
        
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=min(n_results, self.collection.count())
        )

        formatted_results = []
        if results and "documents" in results and results["documents"] and results["documents"][0]:
            docs = results["documents"][0]
            metas = results["metadatas"][0]
            ids = results["ids"][0]
            
            for doc, meta, cid in zip(docs, metas, ids):
                formatted_results.append({
                    "cve_id": cid,
                    "description": doc,
                    "severity": meta.get("severity"),
                    "cvss": meta.get("cvss")
                })

        return formatted_results