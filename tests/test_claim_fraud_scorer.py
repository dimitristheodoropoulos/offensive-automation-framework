from insurance.claim_fraud_scorer import score_claim


def test_high_risk_claim_detected():
    claim = {
        "claim_id": "CLM-1",
        "claim_amount": 9000.0,
        "historical_avg_claim_amount": 2000.0,
        "claim_type": "auto",
        "policy_start_date": "2026-07-01",
        "claim_date": "2026-07-10",
        "submitted_docs": [],
        "prior_claims_count": 5,
    }
    result = score_claim(claim)
    assert result["risk_level"] == "high"
    signal_ids = {s["signal_id"] for s in result["signals"]}
    assert "AMOUNT_DEVIATION" in signal_ids
    assert "EARLY_CLAIM" in signal_ids
    assert "MISSING_DOCUMENTATION" in signal_ids
    assert "CLAIM_FREQUENCY" in signal_ids


def test_low_risk_claim_passes_clean():
    claim = {
        "claim_id": "CLM-2",
        "claim_amount": 2100.0,
        "historical_avg_claim_amount": 2000.0,
        "claim_type": "auto",
        "policy_start_date": "2020-01-01",
        "claim_date": "2026-07-20",
        "submitted_docs": ["police_report", "photos", "repair_estimate"],
        "prior_claims_count": 0,
    }
    result = score_claim(claim)
    assert result["risk_level"] == "low"
    assert result["signals"] == []


def test_date_inconsistency_detected():
    claim = {
        "claim_id": "CLM-3",
        "claim_amount": 1000.0,
        "historical_avg_claim_amount": 1000.0,
        "claim_type": "travel",
        "policy_start_date": "2026-08-01",
        "claim_date": "2026-07-01",
        "submitted_docs": ["boarding_pass", "receipt", "incident_report"],
        "prior_claims_count": 0,
    }
    result = score_claim(claim)
    signal_ids = {s["signal_id"] for s in result["signals"]}
    assert "DATE_INCONSISTENCY" in signal_ids
