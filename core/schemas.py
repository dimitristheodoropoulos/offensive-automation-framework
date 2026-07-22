from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class VulnerabilityRecord(BaseModel):
    vuln_id: str = Field(..., description="Unique identifier (e.g., CVE-ID or custom code)")
    title: str = Field(..., description="Short title of the vulnerability")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    description: str = Field(..., description="Detailed explanation of the issue")
    remediation: Optional[str] = Field(None, description="Suggested or generated fix/patch")

class ToolExecutionResult(BaseModel):
    tool_name: str = Field(..., description="Name of the executing tool or adapter")
    target: str = Field(..., description="Target IP, domain, or endpoint scanned")
    status: str = Field(..., description="Execution status: SUCCESS, FAILED, TIMEOUT")
    vulnerabilities: List[VulnerabilityRecord] = Field(default_factory=list, description="Discovered issues")
    raw_metadata: Dict[str, Any] = Field(default_factory=dict, description="Raw outputs or diagnostic telemetry")