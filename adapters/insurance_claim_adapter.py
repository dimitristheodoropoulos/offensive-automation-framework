from core.adapters import BaseToolAdapter
from core.schemas import ToolExecutionResult, VulnerabilityRecord
from insurance.claim_fraud_scorer import score_claim


class InsuranceClaimFraudAdapter(BaseToolAdapter):
    """
    Adapter που τρέχει το rule-based fraud/risk scoring πάνω σε ένα claim record
    και επιστρέφει το αποτέλεσμα στο ίδιο τυποποιημένο Pydantic contract (ToolExecutionResult /
    VulnerabilityRecord) που χρησιμοποιεί ήδη το OSAF -- εδώ κάθε "VulnerabilityRecord"
    αναπαριστά ένα fraud/risk signal αντί για μια security ευπάθεια.
    """

    @property
    def name(self) -> str:
        return "insurance_claim_fraud_scorer"

    def execute(self, target: str, **kwargs) -> ToolExecutionResult:
        claim = kwargs.get("claim")
        if claim is None:
            raise ValueError("InsuranceClaimFraudAdapter.execute requires a 'claim' kwarg (ClaimRecord dict).")

        result = score_claim(claim)

        records = [
            VulnerabilityRecord(
                vuln_id=signal["signal_id"],
                title=signal["title"],
                severity=signal["severity"],
                description=signal["description"],
                remediation="Escalate to human underwriter for manual review." if signal["severity"] == "HIGH"
                            else "Flag for secondary automated review pass.",
            )
            for signal in result["signals"]
        ]

        return ToolExecutionResult(
            tool_name=self.name,
            target=target,  # εδώ: το claim_id
            status="SUCCESS",
            vulnerabilities=records,
            raw_metadata={
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "signals_count": len(result["signals"]),
            },
        )
