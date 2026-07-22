# orchestration/sanitizer.py
import re
from typing import Any, Dict, List

class PromptInjectionSanitizer:
    """
    Guardrail module against Indirect Prompt Injection attacks.
    Filters raw tool outputs (scraped web pages, headers, banners) 
    before passing them into the LLM context window.
    """
    
    # Μοτίβα επιθέσεων Prompt Injection
    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        r"(?i)disregard\s+above\s+directives",
        r"(?i)system\s*:\s*you\s+are\s+now",
        r"(?i)forget\s+(all\s+)?prior\s+rules",
        r"(?i)new\s+system\s+prompt",
        r"(?i)you\s+must\s+output\s+the\s+following",
        r"(?i)override\s+security\s+policy",
        r"(?i)<script\b[^>]*>.*?</script>"
    ]

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """
        Εντοπίζει και εξουδετερώνει προσπάθειες Prompt Injection 
        και περικλείει το output σε ασφαλή XML boundaries.
        """
        if not isinstance(text, str):
            return text

        sanitized = text
        for pattern in cls.INJECTION_PATTERNS:
            sanitized = re.sub(pattern, "[REDACTED_POTENTIAL_PROMPT_INJECTION]", sanitized)

        # Οριοθέτηση untrusted δεδομένων για το LLM Context
        return f"<untrusted_tool_data>\n{sanitized}\n</untrusted_tool_data>"

    @classmethod
    def sanitize_findings(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Καθαρίζει αναδρομικά όλα τα string fields μιας λίστας ευρημάτων.
        """
        sanitized_list = []
        for item in findings:
            if isinstance(item, dict):
                clean_item = {}
                for key, val in item.items():
                    if isinstance(val, str):
                        clean_item[key] = cls.sanitize_text(val)
                    else:
                        clean_item[key] = val
                sanitized_list.append(clean_item)
            else:
                sanitized_list.append(item)
        return sanitized_list