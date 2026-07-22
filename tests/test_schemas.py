import pytest
from core.schemas import VulnerabilityRecord, ToolExecutionResult

def test_vulnerability_record_valid():
    vuln = VulnerabilityRecord(
        vuln_id="TEST-01",
        title="Test Vulnerability",
        severity="HIGH",
        description="This is a test description",
        remediation="Fix it"
    )
    assert vuln.vuln_id == "TEST-01"
    assert vuln.severity == "HIGH"
    assert vuln.remediation == "Fix it"

def test_tool_execution_result_structure():
    vuln = VulnerabilityRecord(
        vuln_id="TEST-02",
        title="Another Vulnerability",
        severity="LOW",
        description="Desc"
    )
    result = ToolExecutionResult(
        tool_name="test_tool",
        target="127.0.0.1",
        status="SUCCESS",
        vulnerabilities=[vuln],
        raw_metadata={"key": "value"}
    )
    assert result.tool_name == "test_tool"
    assert result.target == "127.0.0.1"
    assert len(result.vulnerabilities) == 1
    assert result.raw_metadata["key"] == "value"