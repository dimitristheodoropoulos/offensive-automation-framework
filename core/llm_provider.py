# core/llm_provider.py
import os
from typing import Optional, Any

try:
    from langchain_ollama import ChatOllama
    OLLAMA_AVAILABLE = True
except ImportError:
    try:
        from langchain_community.chat_models import ChatOllama
        OLLAMA_AVAILABLE = True
    except ImportError:
        OLLAMA_AVAILABLE = False


class LocalLLMProvider:
    def __init__(self, model_name: str = "llama3", base_url: str = "http://localhost:11434"):
        """
        Αρχικοποίηση του παρόχου τοπικού LLM μέσω Ollama.
        """
        self.model_name = os.getenv("OSAF_OLLAMA_MODEL", model_name)
        self.base_url = os.getenv("OLLAMA_BASE_URL", base_url)
        self.llm = self._init_llm()

    def _init_llm(self) -> Optional[Any]:
        if not OLLAMA_AVAILABLE:
            print("[!] [Local LLM] langchain-ollama / langchain-community packages not found.")
            return None

        try:
            # Δημιουργία instance ChatOllama για συμβατότητα με LangGraph agents
            llm = ChatOllama(
                model=self.model_name,
                base_url=self.base_url,
                temperature=0.1
            )
            print(f"[+] [Local LLM] Successfully initialized Ollama with model '{self.model_name}' at {self.base_url}")
            return llm
        except Exception as e:
            print(f"[!] [Local LLM] Initialization failed: {e}")
            return None

    def get_model(self):
        """Επιστρέφει το chat model instance για χρήση στα agent nodes."""
        return self.llm


# Global helper instance
_llm_provider = LocalLLMProvider()

def get_local_llm():
    """Επιστρέφει ενεργό local LLM ή None αν δεν είναι διαθέσιμο."""
    return _llm_provider.get_model()