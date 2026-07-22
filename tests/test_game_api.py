# tests/test_game_api.py
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.game_api_analyzer import GameAPIAnalyzer
from orchestration.tools import game_api_sast_tool


class TestGameAPIScanner(unittest.TestCase):

    def setUp(self):
        self.analyzer = GameAPIAnalyzer()

    def test_grpc_reflection_detection(self):
        """Ελέγχει αν εντοπίζεται η επικίνδυνη ρύθμιση gRPC Reflection."""
        findings = self.analyzer.inspect_grpc_reflection("grpc.game.local", 50051)
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["type"], "gRPC Misconfiguration")

    def test_game_api_sast_tool_execution(self):
        """Επιβεβαιώνει την εκτέλεση του LangChain Tool και το sanitization των ευρημάτων."""
        results = game_api_sast_tool.invoke({
            "base_url": "https://api.examplegame.com",
            "grpc_host": "grpc.examplegame.com"
        })
        self.assertIsInstance(results, list)
        if len(results) > 0:
            # Επιβεβαίωση ότι τα αποτελέσματα έχουν περάσει από το contextual isolation
            first_issue = str(results[0])
            self.assertTrue("<untrusted_tool_data>" in first_issue)


if __name__ == "__main__":
    unittest.main()