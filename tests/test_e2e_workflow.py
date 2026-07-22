import sys
import os
from unittest.mock import patch, MagicMock

# 1. Ορισμός εικονικού API key ΠΡΙΝ γίνει φόρτωση των modules
os.environ["GOOGLE_API_KEY"] = "mock_key_for_offline_testing"
os.environ["GEMINI_API_KEY"] = "mock_key_for_offline_testing"

# Προσθήκη του root directory στο PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_e2e_workflow_offline():
    print("[*] Initiating 100% Offline E2E LangGraph Integration Test with Report Node...")

    # 2. Mocking του Gemini LLM Response
    mock_llm_response = MagicMock()
    mock_llm_response.content = "Analysis complete: High severity SQL Injection vulnerability identified."

    # 3. Mocking των HTTP requests (ZAP API Proxy & REST calls)
    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "alerts": [
            {
                "alert": "SQL Injection - Mocked Target",
                "risk": "High",
                "url": "http://127.0.0.1:3000/#/search"
            }
        ]
    }

    # Εφαρμογή των mocks στο context εκτέλεσης
    with patch("langchain_google_genai.ChatGoogleGenerativeAI.invoke", return_value=mock_llm_response), \
         patch("requests.get", return_value=mock_http_response), \
         patch("requests.post", return_value=mock_http_response):

        # Import του graph μέσα στο patched context
        from orchestration.graph import agent_app

        initial_state = {
            "target": "127.0.0.1",
            "history": [],
            "scan_results": [],
            "enriched_cves": [],
            "web_vulnerabilities": [],
            "next_action": ""
        }

        print("[*] Invoking LangGraph state machine (Deterministic Offline Mode)...")
        final_state = agent_app.invoke(initial_state)

        print("\n" + "=" * 60)
        print("📋 [OFFLINE INTEGRATION TEST RESULTS]")
        print("=" * 60)
        print(f"• Total Log Entries Recorded : {len(final_state.get('history', []))}")
        print(f"• Total Web Findings Found   : {len(final_state.get('web_vulnerabilities', []))}")
        print(f"• Final State Next Action    : '{final_state.get('next_action')}'")
        print("=" * 60)

        # 4. Assertions (Έλεγχοι εγκυρότητας)
        assert isinstance(final_state, dict), "Error: State is not a dictionary"
        assert len(final_state.get("history", [])) > 0, "Error: History log is empty"
        assert final_state.get("next_action") == "end", f"Expected 'end', got '{final_state.get('next_action')}'"
        assert len(final_state.get("web_vulnerabilities", [])) > 0, "Error: Expected vulnerabilities to be populated"
        
        # Έλεγχος ότι η αναφορά δημιουργήθηκε επιτυχώς
        report_path = "reports/pentest_report_127.0.0.1.md"
        assert os.path.exists(report_path), f"Error: Final report file was not created at {report_path}"

        print(f"\n[✓] Report node executed and file successfully generated at '{report_path}'!")


if __name__ == "__main__":
    test_e2e_workflow_offline()