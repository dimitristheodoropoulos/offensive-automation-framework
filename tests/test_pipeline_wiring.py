# tests/test_pipeline_wiring.py
import pytest
from orchestration.tools import (
    economy_auditor_tool,
    netcode_desync_fuzzer_tool,
    local_llm_critic_tool
)

def test_economy_auditor_tool_wrapper():
    # Εκτέλεση του LangChain tool (offline / mock target)
    result = economy_auditor_tool.invoke({"target_base_url": "http://127.0.0.1:3000"})
    assert isinstance(result, (dict, list))

def test_netcode_desync_fuzzer_tool_wrapper():
    result = netcode_desync_fuzzer_tool.invoke({"target_host": "127.0.0.1", "target_port": 7777})
    assert isinstance(result, (dict, list))

def test_local_llm_critic_tool_offline():
    review = local_llm_critic_tool.invoke({"findings_summary": "Test finding: Race Condition in store."})
    assert isinstance(review, str)
    assert len(review) > 0