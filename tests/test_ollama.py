# tests/test_ollama.py
from core.llm_provider import LocalLLMProvider, get_local_llm

def test_local_llm_provider_initialization():
    provider = LocalLLMProvider(model_name="llama3")
    assert provider.model_name == "llama3"
    assert provider.base_url == "http://localhost:11434"

def test_get_local_llm_wrapper():
    model = get_local_llm()
    # Εφόσον το test τρέχει offline, ελέγχουμε ότι η συνάρτηση επιστρέφει αντικείμενο ή None χωρίς να κρασάρει
    assert model is None or hasattr(model, "invoke")