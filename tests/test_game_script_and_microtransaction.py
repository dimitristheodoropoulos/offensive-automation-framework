# tests/test_game_script_and_microtransaction.py
from scanner.game_script_sast import GameScriptAnalyzer
from scanner.microtransaction_analyzer import MicrotransactionAuditor
from orchestration.tools import game_script_sast_tool, microtransaction_audit_tool

def test_game_script_sast_analyzer():
    analyzer = GameScriptAnalyzer()
    sample_lua = """
    local config = {
        api_key = "AIzaSyDummyKeyForTestingOnly123456",
        timeout = 30
    }
    """
    findings = analyzer.scan_script_content("config.lua", sample_lua)
    assert len(findings) > 0
    assert findings[0]["name"] == "Hardcoded API Key"
    assert findings[0]["risk"] == "High"

def test_game_script_sast_clean():
    analyzer = GameScriptAnalyzer()
    clean_lua = "local x = 10 + 20;"
    findings = analyzer.scan_script_content("safe.lua", clean_lua)
    assert findings[0]["name"] == "Game Script SAST Clean"

def test_microtransaction_auditor():
    auditor = MicrotransactionAuditor("http://localhost:8080")
    result = auditor.audit_endpoints()
    assert result["target"] == "http://localhost:8080"
    assert len(result["vulnerabilities"]) >= 2
    assert any("Microtransaction" in v["name"] for v in result["vulnerabilities"])

def test_tools_wrappers():
    # Test LangChain tool wrappers using exact parameter names expected by the tool (filename, content)
    sast_res = game_script_sast_tool.invoke({
        "filename": "test.py", 
        "content": "auth_token = 'secret_token_1234567890abcdef'"
    })
    assert isinstance(sast_res, list)
    
    micro_res = microtransaction_audit_tool.invoke({
        "base_url": "http://game-backend.local"
    })
    assert isinstance(micro_res, dict)
    assert "vulnerabilities" in micro_res