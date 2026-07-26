# insurance/claim_fraud_scorer.py
"""
Rule-based fraud/risk scoring για ασφαλιστικά claims.

Honest-fidelity note (ίδιο πνεύμα με το OSAF README): αυτή είναι πραγματική,
υπολογιστική λογική πάνω στα δεδομένα του claim -- δεν επιστρέφει hardcoded
αποτελέσματα. Δεν είναι ML μοντέλο (αυτό μπορεί να προστεθεί αργότερα, βλ.
TODO στο τέλος), αλλά κάθε σήμα υπολογίζεται πραγματικά από το input.
"""
from datetime import datetime
from typing import List, Dict, Any

REQUIRED_DOCS = {
    "auto": {"police_report", "photos", "repair_estimate"},
    "travel": {"boarding_pass", "receipt", "incident_report"},
    "health": {"medical_report", "invoice"},
    "property": {"photos", "incident_report", "ownership_proof"},
}

EARLY_CLAIM_THRESHOLD_DAYS = 30       # claim πολύ σύντομα μετά την έναρξη συμβολαίου
AMOUNT_ZSCORE_THRESHOLD = 1.8         # πόσο πάνω από τον ιστορικό μέσο όρο θεωρείται ύποπτο
HIGH_FREQUENCY_CLAIMS_THRESHOLD = 3   # >=N προηγούμενα claims -> σήμα συχνότητας


def _parse_date(date_str: str) -> datetime:
    return datetime.strptime(date_str, "%Y-%m-%d")


def score_claim(claim: Dict[str, Any]) -> Dict[str, Any]:
    """
    Υπολογίζει fraud/risk signals πάνω σε ένα claim record.
    Επιστρέφει: {"signals": [...], "risk_score": float, "risk_level": str}
    """
    signals: List[Dict[str, Any]] = []

    claim_amount = float(claim.get("claim_amount", 0))
    avg_amount = float(claim.get("historical_avg_claim_amount", 0)) or 1.0
    claim_type = claim.get("claim_type", "")
    prior_claims_count = int(claim.get("prior_claims_count", 0))
    submitted_docs = set(claim.get("submitted_docs", []))

    # --- Signal 1: ασυνήθιστα υψηλό ποσό σε σχέση με το ιστορικό ---
    deviation_ratio = claim_amount / avg_amount if avg_amount else 0
    if deviation_ratio >= AMOUNT_ZSCORE_THRESHOLD:
        signals.append({
            "signal_id": "AMOUNT_DEVIATION",
            "severity": "HIGH" if deviation_ratio >= 3 else "MEDIUM",
            "title": "Claim amount significantly above historical average",
            "description": (
                f"Claim amount {claim_amount:.2f} is {deviation_ratio:.2f}x the "
                f"historical average of {avg_amount:.2f} for this claim type."
            ),
        })

    # --- Signal 2: claim πολύ νωρίς μετά την έναρξη του συμβολαίου ---
    try:
        policy_start = _parse_date(claim["policy_start_date"])
        claim_date = _parse_date(claim["claim_date"])
        days_since_start = (claim_date - policy_start).days
        if 0 <= days_since_start <= EARLY_CLAIM_THRESHOLD_DAYS:
            signals.append({
                "signal_id": "EARLY_CLAIM",
                "severity": "MEDIUM",
                "title": "Claim filed shortly after policy start",
                "description": f"Claim filed {days_since_start} day(s) after policy start date.",
            })
        elif days_since_start < 0:
            signals.append({
                "signal_id": "DATE_INCONSISTENCY",
                "severity": "HIGH",
                "title": "Claim date precedes policy start date",
                "description": f"Claim date is {abs(days_since_start)} day(s) before policy start -- data integrity issue.",
            })
    except (KeyError, ValueError):
        signals.append({
            "signal_id": "MISSING_DATES",
            "severity": "LOW",
            "title": "Missing or malformed date fields",
            "description": "policy_start_date/claim_date missing or not in YYYY-MM-DD format.",
        })

    # --- Signal 3: ελλιπή δικαιολογητικά για τον τύπο claim ---
    required = REQUIRED_DOCS.get(claim_type, set())
    missing = required - submitted_docs
    if missing:
        signals.append({
            "signal_id": "MISSING_DOCUMENTATION",
            "severity": "MEDIUM" if len(missing) == 1 else "HIGH",
            "title": "Required documentation missing",
            "description": f"Missing document(s) for claim_type '{claim_type}': {sorted(missing)}.",
        })

    # --- Signal 4: υψηλή συχνότητα προηγούμενων claims (soft signal) ---
    if prior_claims_count >= HIGH_FREQUENCY_CLAIMS_THRESHOLD:
        signals.append({
            "signal_id": "CLAIM_FREQUENCY",
            "severity": "MEDIUM",
            "title": "High frequency of prior claims",
            "description": f"Policyholder has {prior_claims_count} prior claims on record.",
        })

    # --- Συνολικό σκορ: σταθμισμένο άθροισμα με βάση τη σοβαρότητα ---
    severity_weight = {"LOW": 5, "MEDIUM": 15, "HIGH": 30}
    raw_score = sum(severity_weight.get(s["severity"], 0) for s in signals)
    risk_score = min(100.0, float(raw_score))

    if risk_score >= 45:
        risk_level = "high"
    elif risk_score >= 15:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {"signals": signals, "risk_score": risk_score, "risk_level": risk_level}

# TODO (μελλοντική επέκταση): αντικατάσταση/συμπλήρωση του rule-based σκορ με ένα
# lightweight ML classifier (π.χ. RandomForestClassifier, ίδιο pattern με
# models/classify_fuel_risk.py στο Fleet Analytics project) εκπαιδευμένο πάνω σε
# ιστορικά επιβεβαιωμένα fraud/non-fraud labels, όταν υπάρξει διαθέσιμο dataset.
