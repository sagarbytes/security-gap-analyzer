"""
Input guardrails — multi-layer prompt-injection detection and input sanitisation.

Detection layers (applied in order):
  1. Hard-block patterns    — explicit injection keywords (original + expanded)
  2. Intent classification  — score-based pre-processor: classifies input as
                              "normal" vs "injection attempt" using weighted signals
  3. Sensitive-data probes  — requests targeting system prompt / internal rules /
                              hidden logic / model identity
  4. Semantic / indirect    — indirect phrasing: poem, summary, translate, explain,
                              haiku, story, metaphor, etc. wrapping extraction intent
  5. Structural attacks     — delimiter smuggling, token-boundary abuse, homoglyphs,
                              excessive special characters
  6. Encoding / obfuscation — base64, hex payloads, Unicode escape sequences
  7. Output sanitiser       — scrubs any LLM response that accidentally echoes
                              internal system context (called from assessor.py)
"""
from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple




MAX_INPUT_LENGTH = 3000

_INTENT_THRESHOLD = 3


# ─────────────────────────────────────────────────────────────
# Layer 1 — Hard-block explicit injection patterns
# (Original set + significantly expanded coverage)
# ─────────────────────────────────────────────────────────────

_HARD_BLOCK_PATTERNS: list[str] = [

    # ── Direct instruction override ──
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(the\s+)?system\s+prompt",
    r"forget\s+(everything|all|your)\s+(previous|prior|above)",
    r"override\s+(your|the)\s+(instructions|rules|prompt|system)",
    r"do\s+not\s+follow\s+(your|the)\s+(instructions|rules|guidelines|constraints)",
    r"bypass\s+(your\s+)?(safety|filter|restriction|guardrail|constraint)",
    r"disable\s+(your\s+)?(safety|filter|restriction|guardrail)",
    r"(unlock|remove)\s+(your\s+)?(restriction|limit|filter|constraint)",
    r"from\s+now\s+on\s+(ignore|forget|disregard)",
    r"new\s+instructions?\s*:",
    r"updated?\s+instructions?\s*:",

    # ── Role / persona hijacking ──
    r"you\s+are\s+now\s+(in\s+)?(developer|debug|god|admin|unrestricted|jailbreak|dan|stan)\s+mode",
    r"act\s+as\s+.{0,40}(hacker|malware|assistant|chatgpt|gpt|unrestricted|without\s+restriction)",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"roleplay\s+as\s+",
    r"switch\s+to\s+.{0,20}mode",
    r"you\s+are\s+(now\s+)?a\s+(different|new|unrestricted|free)\s+(ai|model|assistant|bot)",
    r"your\s+(true|real|actual|hidden)\s+(self|identity|purpose|goal|instruction)",
    r"your\s+(new|updated|real)\s+(role|task|job|function|purpose)\s+is",
    r"(imagine|assume|suppose)\s+you\s+(have\s+no|lack\s+any)\s+(restriction|limit|filter|rule)",

    # ── Explicit system prompt extraction ──
    r"reveal\s+the\s+system\s+prompt",
    r"(print|show|display|output|repeat|recite|list|share|give|tell)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?|directives?)",
    r"what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?|rules?|directives?)",
    r"(copy|paste|echo|dump)\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration)",
    r"(start|begin)\s+with\s+your\s+(system\s+)?prompt",
    r"reveal\s+(your\s+)?(internal|hidden|secret|underlying)\s+(rules?|directives?|instructions?|logic|guidelines?)",
    r"list\s+(your\s+|all\s+|the\s+)?(internal|hidden|secret)?\s*(rules?|restrictions?|directives?|instructions?|guidelines?|constraints?)",

    # ── Data exfiltration ──
    r"exfiltrate|leak|dump\s+secrets?",
    r"send\s+(data|info|information)\s+to\s+",
    r"(extract|retrieve|obtain|access|read)\s+(your\s+)?(internal|hidden|private|secret)\s+(data|instructions?|rules?|config|logic)",

    # ── Structural delimiter injection ──
    r"```\s*(system|assistant|user)\s*\n",
    r"<\|?(system|im_start|im_end|endoftext)\|?>",
    r"###\s*(system|instruction|new\s+prompt|override)",
    r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]",
    r"</?s>|<\|system\|>|<\|user\|>|<\|assistant\|>",
    r"<<SYS>>|<</SYS>>",

    # ── Known jailbreak handles ──
    r"\bDAN\s*[:;—]",
    r"\bSTAN\s*[:;—]",
    r"\bDANTE\b|\bAIM\b|\bCHARLIE\b",
    r"\bjailbreak\b",
    r"do\s+anything\s+now",
    r"(evil|dark|shadow|unrestricted)\s+(mode|version|persona)",

    # ── Second-order attacks ──
    r"when\s+(asked|prompted|told)\s+(to|about)\s+.{0,60}(ignore|bypass|reveal)",
    r"if\s+anyone\s+(asks?|says?|tells?)\s+you\s+to\s+(ignore|reveal|bypass)",
    r"(future|next)\s+(prompt|input|message|instruction)\s+(will|should|must)\s+(ignore|bypass|override)",
]

_HARD_BLOCK_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _HARD_BLOCK_PATTERNS]


# ─────────────────────────────────────────────────────────────
# Layer 2 — Intent-based scoring pre-processor
# ─────────────────────────────────────────────────────────────

class _ScoredSignal(NamedTuple):
    pattern: re.Pattern
    weight: int
    label: str


def _build_scored_signals() -> list[_ScoredSignal]:
    """
    Weight-based signals for intent classification.
    Total score >= _INTENT_THRESHOLD → classified as injection attempt.
    """
    raw: list[tuple[str, int, str]] = [

        # High-weight: clearly adversarial intent
        (r"\b(ignore|bypass|disable|remove|override|circumvent)\b.{0,30}\b(rule|filter|limit|restriction|guardrail|instruction|constraint|safety)\b", 3, "instruction_override"),
        (r"\b(reveal|expose|exfiltrate|extract|leak|dump|steal)\b.{0,30}\b(prompt|instruction|rule|secret|config|internal|hidden|system)\b", 3, "data_extraction"),
        (r"\b(pretend|roleplay|simulate|act|imagine|assume)\b.{0,30}\b(no\s+restriction|without\s+limit|unrestricted|free\s+to|allowed\s+to)\b", 3, "persona_hijack"),

        # Medium-weight: suspicious combinations
        (r"\b(tell|show|give|share|explain|describe|write)\b.{0,50}\b(system|internal|hidden|secret|underlying)\b.{0,30}\b(instruction|rule|prompt|logic|configuration|behavior)\b", 2, "indirect_extraction"),
        (r"\b(what|how|why)\b.{0,20}\b(you\s+are|you\s+were|you\s+must|you\s+should|you\s+have\s+to)\b.{0,30}\b(trained|programmed|configured|instructed|constrained|told)\b", 2, "identity_probe"),
        (r"\b(new|different|alternative|another)\s+(instruction|prompt|rule|role|task|goal|purpose)\b", 2, "instruction_replacement"),
        (r"\b(without|ignoring|forgetting|skipping|disabling)\b.{0,20}\b(your|the)\b.{0,20}\b(rule|instruction|limit|filter|restriction|constraint)\b", 2, "filter_bypass"),

        # Lower-weight: indirect / ambiguous signals
        (r"\b(recite|repeat|copy|paste|echo|quote)\b.{0,30}\b(above|below|previous|your|the)\b", 1, "echo_attempt"),
        (r"\b(before|prior|above|earlier)\s+(message|instruction|prompt|context|system)\b", 1, "context_reference"),
        (r"\bhidden\s+(instruction|rule|directive|message|prompt|mode)\b", 2, "hidden_instruction_probe"),
        (r"\bsecret\s+(instruction|rule|directive|mode|capability|feature|command)\b", 2, "secret_probe"),
        (r"\b(true|real|actual|original)\s+(instruction|purpose|goal|identity|self|rule)\b", 2, "identity_extraction"),
        (r"\b(training|fine.?tuning|base\s+model)\s+(data|examples?|instruction)\b", 1, "training_probe"),
        (r"\bcontext\s+window\b|\bprompt\s+length\b|\btoken\s+limit\b", 1, "technical_probe"),
    ]
    return [_ScoredSignal(re.compile(pat, re.IGNORECASE | re.DOTALL), w, lbl) for pat, w, lbl in raw]


_SCORED_SIGNALS = _build_scored_signals()


def _intent_score(text: str) -> tuple[int, list[str]]:
    """Return (total_score, list_of_triggered_labels)."""
    t = text.lower()
    score = 0
    triggered: list[str] = []
    for sig in _SCORED_SIGNALS:
        if sig.pattern.search(t):
            score += sig.weight
            triggered.append(sig.label)
    return score, triggered


# ─────────────────────────────────────────────────────────────
# Layer 3 — Sensitive data access probe detection
# ─────────────────────────────────────────────────────────────

_SENSITIVE_PROBE_PATTERNS: list[str] = [

    # System / internal architecture probes
    r"\b(system\s+prompt|system\s+message|system\s+instruction|system\s+context)\b",
    r"\b(internal\s+(rule|rules|logic|instruction|instructions|directive|directives|configuration|architecture))\b",
    r"\b(hidden\s+(rule|rules|instruction|instructions|directive|directives|message|layer|prompt))\b",
    r"\b(underlying\s+(model|logic|instruction|instructions|rule|rules|prompt|system|behavior))\b",
    r"\b(meta.?prompt|prompt\s+engineering|prompt\s+template|prompt\s+structure)\b",

    # Model identity / capability probing
    r"\bwhat\s+(model|llm|ai|version|base)\s+(are\s+you|is\s+this|do\s+you\s+use|do\s+you\s+run\s+on)\b",
    r"\b(your\s+)?model\s+(name|version|weights|architecture|parameters)\b",
    r"\b(are\s+you|is\s+this)\s+(gpt|llama|claude|mistral|gemini|palm|falcon|phi)\b",

    # Recitation / verbatim output attacks
    r"\b(recite|verbatim|word\s+for\s+word|character\s+by\s+character)\b.{0,40}\b(instruction|prompt|rule|message|system)\b",
    r"\b(beginning|start)\s+of\s+(your\s+)?(prompt|instruction|message|context|conversation)\b",
    r"\b(output|print|write)\s+(everything|all|any)\s+(you\s+)?(know|have|were\s+given|received)\b",

    # Capability / permission escalation
    r"\b(are\s+you\s+allowed|can\s+you|do\s+you\s+have\s+permission)\s+to\s+(ignore|bypass|reveal|share|disclose)\b",
    r"\b(admin|administrator|superuser|root|developer|god)\s+(mode|access|override|privilege|permission)\b",
    r"\b(unlock|enable|activate)\s+(your\s+)?(full|true|real|unrestricted|hidden)\s+(capability|potential|mode|self)\b",
]

_SENSITIVE_PROBE_COMPILED = [re.compile(p, re.IGNORECASE) for p in _SENSITIVE_PROBE_PATTERNS]


# ─────────────────────────────────────────────────────────────
# Layer 4 — Semantic / indirect phrasing detection
# Catches extraction disguised as creative or academic requests
# ─────────────────────────────────────────────────────────────

_INDIRECT_EXTRACTION_PATTERNS: list[str] = [

    # Creative format wrappers around extraction
    r"\b(write|compose|create|generate)\s+a\s+(poem|haiku|song|rap|story|essay|summary|paragraph|metaphor)\b.{0,80}\b(instruction|instructions|rule|rules|prompt|system|guideline|guidelines|directive|directives)\b",
    r"\b(summarize|paraphrase|translate|reword|rephrase)\b.{0,60}\b(your\s+)?(instruction|instructions|prompt|rule|rules|system|guideline|guidelines|context|directive|directives)\b",
    r"\b(explain|describe|elaborate|clarify)\b.{0,80}\b(how\s+you\s+(work|were\s+built|were\s+made|were\s+configured|were\s+trained|were\s+set\s+up|operate)|your\s+(purpose|role|goal|function|task)|what\s+you\s+do|why\s+you)\b",
    r"\b(in\s+your\s+own\s+words|informally|casually|simply|briefly|concisely)\b.{0,80}\b(instruction|instructions|rule|rules|prompt|system|guideline|restrictions)\b",

    # Indirect framing attacks ("hypothetically", "academically")
    r"\b(hypothetically|theoretically|academically|for\s+educational\s+purposes?|as\s+a\s+research\s+exercise)\b.{0,80}\b(ignore|bypass|reveal|dump|disclose)\b",
    r"\b(hypothetically|theoretically|supposing|imagining)\b.{0,80}\b(no\s+restriction|without\s+limit|no\s+rule|no\s+filter|no\s+constraint)\b",
    r"\b(let.s\s+say|suppose|imagine|what\s+if)\b.{0,60}\b(you\s+had\s+no\s+restriction|you\s+were\s+allowed|there\s+were\s+no\s+rule|had\s+no\s+filter)\b",
    r"\b(as\s+an?\s+(experiment|exercise|test|example|illustration))\b.{0,60}\b(ignore|bypass|reveal|disable)\b",
    r"\bif\s+you\s+had\s+no\s+(restrictions?|limits?|rules?|filters?|guidelines?|constraints?)\b",

    # Obfuscation through negation
    r"\bdo\s+not\s+(refuse|reject|decline|block|deny)\b.{0,40}\b(this|my|the)\s+(request|question|input)\b",
    r"\byou\s+(should|must|have\s+to|need\s+to|are\s+required\s+to)\s+(comply|agree|accept|allow|permit)\b",
    r"\b(there\s+is\s+no\s+(rule|restriction|limit|filter|policy)\s+(that\s+)?(prevents?|stops?|blocks?|forbids?))\b",

    # Indirect self-reference extraction
    r"\b(how\s+were\s+you|were\s+you)\s+(made|built|created|trained|configured|set\s+up|instructed|designed)\b",
    r"\bwhat\s+(instructions?|rules?|guidelines?|directives?|constraints?)\s+(were|have\s+been)\s+(given|provided|set|programmed|loaded)\b",
    r"\b(list|enumerate|outline)\s+(all\s+)?(your\s+|the\s+)?(internal\s+)?(rules?|restrictions?|directives?|instructions?|guidelines?|constraints?)\b",
    r"\bwhat\s+(are\s+you\s+(not\s+)?allowed|can\s+you\s+not|cannot\s+you|you\s+are\s+not\s+allowed)\s+(to\s+)?(do|say|discuss|reveal|share)\b",
    r"\btell\s+me\s+what\s+you\s+(are|were)\s+(not\s+allowed|forbidden|restricted|prohibited|prevented)\b",
]

_INDIRECT_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _INDIRECT_EXTRACTION_PATTERNS]


# ─────────────────────────────────────────────────────────────
# Layer 5 — Structural / delimiter / homoglyph attacks
# ─────────────────────────────────────────────────────────────

# Excessive special characters may indicate delimiter injection
_MAX_SPECIAL_CHAR_RATIO = 0.25
_MIN_TEXT_LENGTH_FOR_RATIO_CHECK = 40

# Unicode confusable sets (Cyrillic, Greek, fullwidth lookalikes used to bypass filters)
_HOMOGLYPH_SUSPICIOUS_RANGES = [
    (0x0400, 0x04FF),   # Cyrillic
    (0x0370, 0x03FF),   # Greek
    (0xFF00, 0xFFEF),   # Fullwidth/Halfwidth Forms
    (0x2000, 0x206F),   # General Punctuation (zero-width, non-breaking spaces etc.)
]

def _contains_suspicious_unicode(text: str) -> bool:
    """Flag inputs mixing Latin with confusable scripts, or containing zero-width chars."""
    zero_width = {0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x180E}
    for ch in text:
        cp = ord(ch)
        if cp in zero_width:
            return True
        # Flag Cyrillic/Greek lookalikes mixed into otherwise-Latin text
        for start, end in _HOMOGLYPH_SUSPICIOUS_RANGES[:2]:  # Cyrillic + Greek
            if start <= cp <= end:
                # Only flag if it's mixed with lots of ASCII (suspicious cross-script)
                ascii_chars = sum(1 for c in text if ord(c) < 128)
                if ascii_chars / max(len(text), 1) > 0.5:
                    return True
    return False


def _special_char_ratio(text: str) -> float:
    if len(text) < _MIN_TEXT_LENGTH_FOR_RATIO_CHECK:
        return 0.0
    special = sum(1 for ch in text if not ch.isalnum() and ch not in " \t\n.,;:!?'\"-_()")
    return special / len(text)


# ─────────────────────────────────────────────────────────────
# Layer 6 — Encoding / obfuscation detection
# ─────────────────────────────────────────────────────────────

# Base64 run: 30+ consecutive base64 chars (catches chunks within space-separated blobs)
_B64_CHUNK_PATTERN = re.compile(r"[A-Za-z0-9+/]{30,}={0,2}")
# Whole-input base64 check: strip spaces, check if majority is valid base64 chars
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
# Hex dump: 30+ consecutive hex characters
_HEX_PATTERN = re.compile(r"(?:0x)?[0-9a-fA-F]{30,}")
# Unicode escape sequences
_UNICODE_ESC_PATTERN = re.compile(r"(\\u[0-9a-fA-F]{4}){5,}")
# URL-encoded runs
_URL_ENC_PATTERN = re.compile(r"(%[0-9a-fA-F]{2}){10,}")
# ROT13 / Caesar cipher giveaway (long alphabetic run with no vowels)
_NO_VOWEL_PATTERN = re.compile(r"\b[^aeiou\W\d_]{8,}\b", re.IGNORECASE)


def _is_base64_blob(text: str) -> bool:
    """
    Detect base64 payloads that may be space-separated into shorter chunks.
    Strategy 1 — any single chunk >= 30 valid B64 chars.
    Strategy 2 — if the text is mostly B64 chars (>75%) and ends with '=' padding.
    """
    # Strategy 1: chunk detection (lowered to 30 chars)
    if _B64_CHUNK_PATTERN.search(text):
        return True
    # Strategy 2: ratio check for space-separated blobs
    no_space = text.replace(" ", "").replace("\n", "").replace("\t", "")
    if len(no_space) >= 40:
        b64_ratio = sum(1 for c in no_space if c in _B64_CHARS) / len(no_space)
        ends_with_pad = no_space.endswith("=") or no_space.endswith("==")
        if b64_ratio > 0.92 and ends_with_pad:
            return True
    return False


def _encoding_attack_check(text: str) -> str | None:
    if _is_base64_blob(text):
        return "Possible base64-encoded payload detected in input."
    if _HEX_PATTERN.search(text):
        return "Possible hex-encoded payload detected in input."
    if _UNICODE_ESC_PATTERN.search(text):
        return "Possible Unicode escape sequence payload detected in input."
    if _URL_ENC_PATTERN.search(text):
        return "Possible URL-encoded payload detected in input."
    # Check for suspiciously vowel-free runs (ROT/substitution cipher)
    vowel_free = _NO_VOWEL_PATTERN.findall(text)
    if len(vowel_free) >= 4:
        return "Possible obfuscated/encoded text detected in input."
    return None


# ─────────────────────────────────────────────────────────────
# Public API — main detection function
# ─────────────────────────────────────────────────────────────

def detect_prompt_injection(text: str) -> str | None:
    """
    Run all detection layers on the input.
    Returns an error message string if injection is detected, else None.

    Layers applied:
      1. Length guard
      2. Hard-block explicit patterns
      3. Sensitive data access probe patterns
      4. Indirect / semantic phrasing patterns
      5. Structural / special-character / homoglyph checks
      6. Encoding / obfuscation checks
      7. Intent-score pre-processor (weighted signal sum)
    """
    if not text:
        return None

    # ── Layer 0: Length guard ──
    if len(text) > MAX_INPUT_LENGTH:
        return (
            f"Input too long ({len(text)} characters). "
            f"Maximum allowed is {MAX_INPUT_LENGTH} characters."
        )

    t_lower = text.lower()

    # ── Layer 1: Hard-block explicit injection keywords ──
    for pat in _HARD_BLOCK_COMPILED:
        if pat.search(t_lower):
            return "Security policy violation: explicit injection pattern detected. Input blocked."

    # ── Layer 3: Sensitive data access probes ──
    for pat in _SENSITIVE_PROBE_COMPILED:
        if pat.search(t_lower):
            return "Security policy violation: input appears to probe internal system data. Input blocked."

    # ── Layer 4: Indirect / semantic extraction patterns ──
    for pat in _INDIRECT_COMPILED:
        if pat.search(t_lower):
            return "Security policy violation: indirect data-extraction phrasing detected. Input blocked."

    # ── Layer 5: Structural / special-char / homoglyph ──
    if _contains_suspicious_unicode(text):
        return "Security policy violation: suspicious Unicode characters detected in input."

    if _special_char_ratio(text) > _MAX_SPECIAL_CHAR_RATIO:
        return "Security policy violation: abnormal density of special characters detected."

    # ── Layer 6: Encoding / obfuscation ──
    enc_result = _encoding_attack_check(text)
    if enc_result:
        return enc_result

    # ── Layer 2 (scoring last — catches combinations missed above) ──
    score, labels = _intent_score(text)
    if score >= _INTENT_THRESHOLD:
        return (
            f"Security policy violation: input classified as injection attempt "
            f"(intent score={score}, signals={', '.join(labels)}). Input blocked."
        )

    return None


# ─────────────────────────────────────────────────────────────
# Layer 7 — Output guardrails
# Called by assessor.py AFTER LLM response to prevent data leakage
# ─────────────────────────────────────────────────────────────

# Patterns that indicate the LLM accidentally echoed system internals
_OUTPUT_LEAK_PATTERNS: list[str] = [
    r"(my\s+)?(system\s+prompt|system\s+message|system\s+instruction)\s+(is|reads?|says?|states?)",
    r"i\s+(was\s+)?(instructed|told|programmed|configured|asked)\s+to\s+(assess|compare|analyze|evaluate)",
    r"(here\s+(are|is)|the\s+following\s+(are|is))\s+(my\s+)?(instructions?|rules?|guidelines?|directives?)",
    r"(strict|core)\s+(json|output)\s+(format|schema|structure)",
    r"════+",                               # The decorative separator from SYSTEM_PROMPT
    r"STRICT\s+POLICY\s+ADHERENCE",        # Literal header from SYSTEM_PROMPT
    r"CLASSIFICATION\s+RULES",             # Literal header from SYSTEM_PROMPT
    r"my\s+(only\s+)?job\s+is\s+to\s+(compare|assess|analyze|evaluate)",
    r"(you\s+are|i\s+am)\s+a\s+cybersecurity\s+policy\s+auditor",
]

_OUTPUT_LEAK_COMPILED = [re.compile(p, re.IGNORECASE) for p in _OUTPUT_LEAK_PATTERNS]

# Replacement text when a leak is detected in a field
_LEAK_REDACTED = "[REDACTED — internal system context]"


def sanitize_output(text: str | None) -> str | None:
    """
    Scan a single text field from the LLM response for internal data leakage.
    Returns the sanitized string (leaking content replaced with redaction marker),
    or None if input is None.

    Called by assessor.py on summary, gap_detail, and policy_reference fields.
    """
    if not text:
        return text

    result = text
    for pat in _OUTPUT_LEAK_COMPILED:
        if pat.search(result):
            # Replace the entire leaking sentence rather than just the match
            result = pat.sub(_LEAK_REDACTED, result)

    return result
