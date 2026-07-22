# tests/test_ghidra_analyzer.py
import os
import pytest
from scanner.ghidra_headless_analyzer import GhidraHeadlessAnalyzer
from orchestration.tools import ghidra_sast_tool

def test_ghidra_analyzer_with_dummy_binary(tmp_path):
    # Δημιουργία ενός προσωρινού dummy binary αρχείου με κρυμμένα strings
    dummy_bin = tmp_path / "game_client.exe"
    dummy_bin.write_bytes(b"MZ\x90\x00PE\x00\x00 api_key=secret_game_token_999 https://api.gamebackend.com/v1")
    
    analyzer = GhidraHeadlessAnalyzer(str(dummy_bin))
    findings = analyzer.analyze_binary()
    
    assert isinstance(findings, list)
    assert len(findings) > 0
    assert any("Secret" in f.get("name", "") or "Analysis" in f.get("name", "") for f in findings)

def test_ghidra_sast_tool_wrapper(tmp_path):
    dummy_bin = tmp_path / "server_daemon.elf"
    dummy_bin.write_bytes(b"\x7fELFSomeELFHeader password=admin_secure_pass")
    
    result = ghidra_sast_tool.invoke({"binary_path": str(dummy_bin)})
    assert isinstance(result, list)
    assert len(result) > 0