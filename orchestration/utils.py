import re


def extract_json_content(text: str) -> str:
    """
    Αφαιρεί markdown code fences (```json ... ``` ή ``` ... ```) αν το LLM
    τα προσθέσει γύρω από το JSON output, ώστε το json.loads() να μη σκάει.
    """
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)

    # Fallback: αν δεν υπάρχουν code fences, ψάξε το πρώτο { ... } block
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    if match:
        return match.group(1)

    return text.strip()


def sanitize_untrusted_input(data: str, max_length: int = 1000) -> str:
    """
    Sanitizes potentially malicious content from tool outputs.
    Protects against prompt injection via echo-back / indirect injection.
    
    This is a DEFENSIVE LAYER: all external tool outputs (Nmap, ZAP, SQLMap)
    pass through this filter before entering the LLM context.
    """
    if not isinstance(data, str):
        data = str(data)
    
    # Dangerous phrases που θα μπορούσαν να κάνουν override του system prompt
    dangerous_patterns = [
        r"ignore\s+instructions?",
        r"system\s+prompt",
        r"disregard\s+previous",
        r"override\s+",
        r"new\s+instructions?",
        r"forget\s+everything",
        r"execute\s+command",
        r"system\(",
    ]
    
    sanitized = data
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
    
    # Truncate για context window safety
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [TRUNCATED]"
    
    return sanitized