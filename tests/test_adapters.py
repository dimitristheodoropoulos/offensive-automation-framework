import pytest
from core.adapters import ToolRegistry
from core.schemas import ToolExecutionResult
from adapters.proprietary_game_fuzzer import ProprietaryGameFuzzerAdapter

def test_tool_registry_workflow():
    registry = ToolRegistry()
    adapter = ProprietaryGameFuzzerAdapter()
    
    # 1. Έλεγχος εγγραφής (Registration)
    registry.register(adapter)
    assert "proprietary_game_fuzzer" in registry.list_available()
    
    # 2. Έλεγχος ανάκτησης (Retrieval)
    fetched_adapter = registry.get("proprietary_game_fuzzer")
    assert fetched_adapter.name == "proprietary_game_fuzzer"
    
    # 3. Έλεγχος εκτέλεσης και Pydantic δομής εξόδου
    result = fetched_adapter.execute(target="127.0.0.1")
    assert isinstance(result, ToolExecutionResult)
    assert result.status == "SUCCESS"
    assert len(result.vulnerabilities) > 0
    assert result.vulnerabilities[0].vuln_id == "GAME-NET-01"

def test_registry_key_error():
    registry = ToolRegistry()
    with pytest.raises(KeyError):
        registry.get("non_existent_tool")