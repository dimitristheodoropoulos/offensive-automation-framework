# tests/test_netcode_fuzzer.py
from core.netcode_fuzzer import NetcodeDesyncFuzzer

def test_netcode_fuzzer_initialization():
    fuzzer = NetcodeDesyncFuzzer(target_host="127.0.0.1", target_port=7777)
    assert fuzzer.target_host == "127.0.0.1"
    assert fuzzer.target_port == 7777
    assert isinstance(fuzzer.results, list)

def test_netcode_fuzzer_execution():
    fuzzer = NetcodeDesyncFuzzer(target_host="127.0.0.1", target_port=7777)
    result = fuzzer.run_fuzzer_sync(packet_count=50)
    
    assert "protocol" in result
    assert "packets_sent" in result
    assert "desynchronization_risk" in result
    assert "severity" in result
    assert result["packets_sent"] == 50