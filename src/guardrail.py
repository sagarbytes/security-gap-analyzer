"""
Input guardrails — prompt-injection detection and input sanitisation.
"""
from __future__ import annotations

import re




MAX_INPUT_LENGTH = 3000




INJECTION_PATTERNS: list[str] = [
    
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(the\s+)?system\s+prompt",
    r"forget\s+(everything|all|your)\s+(previous|prior|above)",
    r"override\s+(your|the)\s+(instructions|rules|prompt)",
    r"do\s+not\s+follow\s+(your|the)\s+(instructions|rules|guidelines)",

    
    r"you\s+are\s+now\s+(in\s+)?(developer|debug|god|admin|unrestricted)\s+mode",
    r"act\s+as\s+.{0,40}(hacker|malware|assistant|chatgpt|gpt|unrestricted)",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"roleplay\s+as\s+",
    r"switch\s+to\s+.{0,20}mode",

    
    r"reveal\s+the\s+system\s+prompt",
    r"(print|show|display|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions)",
    r"what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions)",

    
    r"exfiltrate|leak|dump\s+secrets?",
    r"send\s+(data|info|information)\s+to\s+",

    
    r"```\s*(system|assistant)\s*\n",
    r"<\|?(system|im_start|endoftext)\|?>",
    r"###\s*(system|instruction|new\s+prompt)",
    r"\[INST\]|\[/INST\]",

    
    r"DAN\s*[:;]",
    r"STAN\s*[:;]",
    r"jailbreak",
]


_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


def detect_prompt_injection(text: str) -> str | None:
    """Return an error message if prompt injection is suspected, else None."""
    if not text:
        return None

    
    if len(text) > MAX_INPUT_LENGTH:
        return (
            f"Input too long ({len(text)} characters). "
            f"Maximum allowed is {MAX_INPUT_LENGTH} characters."
        )

    t = text.lower()

    
    for pat in _COMPILED_PATTERNS:
        if pat.search(t):
            return f"Possible prompt injection detected (matched pattern)."

    
    
    b64_match = re.search(r"[A-Za-z0-9+/]{60,}={0,2}", text)
    if b64_match:
        return "Possible encoded payload detected in input."

    return None
