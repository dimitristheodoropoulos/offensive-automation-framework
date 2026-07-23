"""
tests/test_memory.py

Καλύπτει το νέο cross-run "memory management" feature:
- database.get_target_history()
- database.summarize_target_memory()
- orchestration.state.new_state()'s prior_scan_context default

Κάθε test χρησιμοποιεί ένα προσωρινό SQLite αρχείο (μέσω monkeypatch στο database.DB_PATH),
ώστε να μην αγγίζει ποτέ το πραγματικό reports/osaf_history.db.
"""
import pytest

import database
from orchestration.state import new_state


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Κάθε test τρέχει με το δικό του, καθαρό SQLite αρχείο."""
    db_file = tmp_path / "test_osaf_history.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    yield db_file


class TestGetTargetHistory:
    def test_empty_when_db_file_does_not_exist(self):
        # Δεν έχει κληθεί init_db()/save_scan_result() ακόμα -> το αρχείο δεν υπάρχει
        assert database.get_target_history("127.0.0.1") == []

    def test_empty_when_target_never_scanned(self):
        database.save_scan_result(
            target="10.0.0.5",
            profile="full",
            vulnerabilities_count=2,
            report_data={"web_vulnerabilities": []}
        )
        # Ζητάμε ιστορικό για ΔΙΑΦΟΡΕΤΙΚΟ target
        assert database.get_target_history("192.168.1.1") == []

    def test_returns_saved_scan_for_matching_target(self):
        database.save_scan_result(
            target="127.0.0.1",
            profile="full",
            vulnerabilities_count=3,
            report_data={"web_vulnerabilities": [{"name": "SQL Injection", "risk": "High"}]}
        )
        history = database.get_target_history("127.0.0.1")
        assert len(history) == 1
        assert history[0]["vulnerabilities_count"] == 3
        assert history[0]["profile"] == "full"

    def test_orders_most_recent_first_and_respects_limit(self):
        for i in range(5):
            database.save_scan_result(
                target="127.0.0.1",
                profile="full",
                vulnerabilities_count=i,
                report_data={"web_vulnerabilities": []}
            )
        history = database.get_target_history("127.0.0.1", limit=2)
        assert len(history) == 2
        # Το πιο πρόσφατο (τελευταίο αποθηκευμένο, vulnerabilities_count=4) πρέπει να είναι πρώτο
        assert history[0]["vulnerabilities_count"] == 4
        assert history[1]["vulnerabilities_count"] == 3


class TestSummarizeTargetMemory:
    def test_empty_string_when_no_history(self):
        assert database.summarize_target_memory("127.0.0.1") == ""

    def test_includes_target_name_and_finding_count(self):
        database.save_scan_result(
            target="127.0.0.1",
            profile="full",
            vulnerabilities_count=2,
            report_data={"web_vulnerabilities": [
                {"name": "Verified SQL Injection (MySQL)", "risk": "High"},
                {"name": "Missing Rate-Limiting Headers", "risk": "Medium"},
            ]}
        )
        summary = database.summarize_target_memory("127.0.0.1")

        assert "127.0.0.1" in summary
        assert "2 finding(s)" in summary
        assert "Verified SQL Injection (MySQL)" in summary
        assert "Missing Rate-Limiting Headers" in summary

    def test_handles_malformed_full_report_gracefully(self):
        # full_report δεν είναι valid JSON -> δεν πρέπει να ρίξει exception, μόνο να παραλείψει τα ονόματα
        database.save_scan_result(
            target="127.0.0.1",
            profile="web",
            vulnerabilities_count=1,
            report_data={"web_vulnerabilities": []}
        )
        # Χαλάμε σκόπιμα το αποθηκευμένο full_report ώστε να μην είναι valid JSON
        conn = __import__("sqlite3").connect(database.DB_PATH)
        conn.execute("UPDATE scan_history SET full_report = ? WHERE target = ?", ("{not valid json", "127.0.0.1"))
        conn.commit()
        conn.close()

        summary = database.summarize_target_memory("127.0.0.1")
        assert "127.0.0.1" in summary
        assert "no named findings recorded" in summary

    def test_limit_controls_how_many_prior_runs_are_summarized(self):
        for i in range(4):
            database.save_scan_result(
                target="127.0.0.1",
                profile="full",
                vulnerabilities_count=i,
                report_data={"web_vulnerabilities": []}
            )
        summary = database.summarize_target_memory("127.0.0.1", limit=2)
        # Μία γραμμή τίτλου + 2 γραμμές ιστορικού
        assert summary.count("\n- ") == 2


class TestStateDefaults:
    def test_new_state_defaults_prior_scan_context_to_empty_string(self):
        state = new_state("127.0.0.1")
        assert state["prior_scan_context"] == ""

    def test_new_state_accepts_explicit_prior_scan_context(self):
        state = new_state("127.0.0.1", prior_scan_context="Previous scan history for target '127.0.0.1'...")
        assert "Previous scan history" in state["prior_scan_context"]