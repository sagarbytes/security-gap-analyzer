"""
Rule-based validation after LLM output to reduce false positives.

Uses keyword/heuristic checks on user description vs known policy thresholds.
Combined with LLM reasoning; does not replace retrieval-grounded assessment.

Also provides positive-keyword credit so well-described compliant implementations
are not falsely downgraded.
"""
from __future__ import annotations

import re
from typing import Literal

Severity = Literal["severe", "moderate"]


def _lower(s: str) -> str:
    return (s or "").lower()


# ═══════════════════════════════════════════════════════════════════════════
#  GENERAL BLOCKERS (Gibberish & meaningless input catch-all)
# ═══════════════════════════════════════════════════════════════════════════

def _blockers_general(desc: str) -> list[tuple[str, Severity]]:
    t = desc.strip()
    out: list[tuple[str, Severity]] = []
    
    if not t:
        return out
        
    # Check 1: Absolute length threshold
    if len(t) < 15:
        out.append(("Input lacks sufficient detail to verify compliance.", "severe"))
        return out
        
    # Check 2: Word count and dictionary sanity
    words = [w for w in re.split(r'\s+', t) if w]
    if len(words) < 3:
        out.append(("Input too brief or lacks meaningful context.", "severe"))
        
    # Check 3: Repetition (e.g. "jjjjj", "dddd,ddd")
    if re.search(r"([a-zA-Z])\1{5,}", t):
        out.append(("Input contains repetitive gibberish.", "severe"))
        
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  BLOCKER RULES  (detect policy violations → may downgrade status)
# ═══════════════════════════════════════════════════════════════════════════


def _blockers_authentication(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # MFA missing or partial (Admins only is a Gap)
    if re.search(r"mfa\s+(only|just)\s+for\s+admin|no\s+mfa\b|password\s+only|single[- ]factor", t):
        out.append((
            "Input describes missing or insufficient MFA coverage (e.g. Admins only). Policy requires universal MFA.",
            "severe",
        ))

    # Default credentials not addressed
    if "default" in t and re.search(
        r"default\s+(password|cred|login)|leave\s+default|vendor\s+default|not\s+(rotated|changed)\s+yet", t
    ):
        out.append((
            "Input explicitly describes utilizing or neglecting to rotate vendor default credentials.",
            "severe",
        ))

    return out


def _blockers_logging(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Complete lack of logging
    if re.search(r"no\s+logging|we\s+do\s+not\s+log|logs\s+disabled|never\s+review", t):
        out.append((
            "Input explicitly states no telemetry, logging, or review pipeline is established.",
            "severe",
        ))

    # Only local troubleshooting logs
    if re.search(
        r"only\s+when\s+troubleshoot|local\s+files?\s+only|no\s+central\s+logging",
        t,
    ):
        out.append((
            "Input implies logs are strictly local and inherently lack centralized security visibility.",
            "moderate",
        ))

    return out


def _blockers_session(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Sessions never timeout
    if re.search(r"no\s+timeout|never\s+expire|permanent\s+session|sessions?\s+do\s+not\s+timeout", t):
        out.append((
            "Input declares explicit absence of inactivity timeouts.",
            "severe",
        ))

    # Excessive timeouts (e.g. 60 minutes when policy likely requires 15/5)
    if re.search(r"\b(30|60|90|120)\s*(min|minute)", t) or "1\s*hour" in t:
        out.append((
            "Input describes session timeouts (≥30m) that significantly exceed typical security policy thresholds (15m).",
            "severe",
        ))

    # Missing logout invalidation
    if re.search(r"not\s+invalidated\s+when\s+logout|not\s+invalidated\s+on\s+logout|logout\s+does\s+not\s+expire", t):
        out.append((
            "Input explicitly states session tokens are not invalidated upon user logout.",
            "severe",
        ))

    # Insecure token storage / logic
    if "localstorage" in t or "local storage" in t or "unencrypted" in t:
        out.append((
            "Input indicates high-risk token storage capabilities or plaintext transport.",
            "moderate",
        ))

    # Concurrent logins allowed
    if re.search(r"not\s+prevent\s+concurrent|concurrent\s+logins?\s+(allowed|permitted|not\s+prevented)", t):
        out.append((
            "Input states that concurrent logins are not prevented, contrary to security best practices.",
            "moderate",
        ))

    # Predictable session IDs
    if re.search(r"(?<!non[- ])(?<!un)predictable\s+session|sequential\s+(session|id|token)", t):
        out.append((
            "Input explicitly defines session identifiers as vulnerable or predictable.",
            "severe",
        ))

    return out


def _blockers_patching(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Adhoc or no patching
    if re.search(r"never\s+patch|no\s+formal|ad\s*hoc\s+patch|manual.{0,30}patch\s+only", t):
        out.append((
            "Input explicitly denies possessing an active or automated patching structure.",
            "severe",
        ))

    # Long patch windows (2-3 weeks, 30 days)
    if re.search(r"2-3\s+weeks?|30\s+days?|within\s+a\s+month|whenever\s+staff\s+available", t):
        out.append((
            "Input describes extremely slow vulnerability remediation windows (2+ weeks). Policy requires 48-72h for critical patches.",
            "severe",
        ))

    # Legacy systems without controls
    if re.search(r"legacy|unsupported|end of life|eol", t) and not re.search(
        r"compensat|documented|risk\s+accept|isolated", t
    ):
        out.append((
            "Input relies on EOL legacy systems without mentioning isolation or compensating controls.",
            "moderate",
        ))

    return out


def _blockers_authorization(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Completely unverified access
    if re.search(r"never\s+review|everyone\s+has\s+access|no\s+restrictions", t):
        out.append((
            "Input fundamentally admits to providing completely unrestricted or unreviewed access.",
            "severe",
        ))

    return out


def _blockers_compliance(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    if re.search(r"no\s+(iso|soc)|not\s+certified|no\s+formal\s+audit", t):
        out.append((
            "Policy expects standards alignment, annual internal audits, and 90-day corrective closure.",
            "moderate",
        ))

    # Third-party compliance not mentioned
    if re.search(r"third.party|vendor|external\s+service", t) and not re.search(
        r"soc\s*2|iso\s*27001|compliance\s+verif|audit", t
    ):
        out.append((
            "Policy requires third-party services to undergo compliance verification (SOC 2, ISO 27001).",
            "moderate",
        ))

    return out


def _blockers_hardening(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    if re.search(r"plain\s*text|no\s*(encryption|tls)|public\s+db", t):
        out.append((
            "Input describes extremely insecure basic architecture flaws (plaintext transport or public databases).",
            "severe",
        ))

    return out


# ═══════════════════════════════════════════════════════════════════════════
#  POSITIVE KEYWORD CREDIT  (detect compliance signals → prevent false downgrades)
# ═══════════════════════════════════════════════════════════════════════════

_POSITIVE_KEYWORDS: dict[str, list[str]] = {
    "Authorization": [
        r"\brbac\b", r"role.based", r"least\s+privilege", r"polp",
        r"quarterly\s+(access\s+)?review", r"manager\s+approval",
        r"privileged.{0,40}(monthly|review)", r"access\s+control",
    ],
    "Authentication": [
        r"\bmfa\b.*\b(mandatory|required|enforced|all\s+users)\b",
        r"\b(mandatory|required|enforced)\b.*\bmfa\b",
        r"(12|twelve)\s*(char|charact|minimum)", r"≥\s*12",
        r"certificate.based", r"key.based",
        r"\bsso\b|single\s+sign", r"default\s+cred.{0,30}(removed|changed|rotated)",
    ],
    "Logging & Monitoring": [
        r"\bsiem\b", r"central(ized|ised)?\s+(log|siem)",
        r"1\s*year|365\s*days?|12\s*months?", r"weekly\s+review",
        r"\bntp\b|time\s+sync", r"authentication\s+attempt",
        r"security\s+event", r"anomal",
    ],
    "Certification & Compliance": [
        r"\biso\b.*27001|27001", r"\bsoc\s*2\b",
        r"annual\s+(internal\s+)?audit", r"corrective\s+action",
        r"90\s*day", r"third.party.{0,40}(verif|audit|compli)",
    ],
    "Application Patching": [
        r"48\s*h|two\s*days?|within\s+48", r"critical.{0,40}48",
        r"7\s*days?.{0,20}high|high.{0,40}7\s*days?",
        r"30\s*days?.{0,20}medium|medium.{0,40}30\s*days?",
        r"patch\s+management\s+lifecycle", r"compensat.{0,30}control",
    ],
    "System Hardening": [
        r"tls\s*1\.[23]|tls\s*1\.2\+", r"\bcis\b.*benchmark|benchmark.*\bcis\b",
        r"unnecessary\s+(service|port).{0,30}(disabled|removed)",
        r"admin.{0,40}(segregat|restrict|isolat)",
        r"hardening\s+guide", r"annual.{0,20}review",
    ],
    "Session Management": [
        r"15\s*min.*user|user.*15\s*min",
        r"5\s*min.*privileged|privileged.*5\s*min",
        r"encrypt.{0,20}token|token.{0,20}encrypt",
        r"invalidat.{0,20}logout|logout.{0,20}invalidat",
        r"non.predictable|random.{0,20}(session|token|id)",
        r"simultaneous.{0,30}prevent|prevent.{0,30}simultaneous",
    ],
}


def _count_positive_matches(control_area: str, description: str) -> int:
    """Count how many positive policy-keyword patterns match the description."""
    patterns = _POSITIVE_KEYWORDS.get(control_area, [])
    t = _lower(description)
    return sum(1 for p in patterns if re.search(p, t))


# ═══════════════════════════════════════════════════════════════════════════
#  DISPATCH TABLE
# ═══════════════════════════════════════════════════════════════════════════

BLOCKERS_BY_AREA: dict[str, callable] = {
    "Authorization": _blockers_authorization,
    "Authentication": _blockers_authentication,
    "Logging & Monitoring": _blockers_logging,
    "Certification & Compliance": _blockers_compliance,
    "Application Patching": _blockers_patching,
    "System Hardening": _blockers_hardening,
    "Session Management": _blockers_session,
}


def get_rule_blockers(
    control_area: str, description: str
) -> list[tuple[str, Severity]]:
    fn = BLOCKERS_BY_AREA.get(control_area)
    if not fn:
        return []
    return fn(description)


# ═══════════════════════════════════════════════════════════════════════════
#  APPLY RULE DOWNGRADE  (main entry for post-LLM correction)
# ═══════════════════════════════════════════════════════════════════════════

def apply_rule_downgrade(control_area: str, description: str, current_status: str):
    """
    Balanced logic that considers BOTH blockers and positive signals.

    Returns (new_status, notes_list).
    """
    blockers = _blockers_general(description) + get_rule_blockers(control_area, description)
    positive_count = _count_positive_matches(control_area, description)

    if not blockers:
        return current_status, []

    severe_count = sum(1 for _, s in blockers if s == "severe")
    moderate_count = sum(1 for _, s in blockers if s == "moderate")
    notes = [b[0] for b in blockers]

    # ── Gibberish / Meaningless Text → Gap Identified ──
    if any("Input lacks sufficient detail" in b[0] or "Input too brief" in b[0] or "repetitive gibberish" in b[0] for b in blockers):
        return "Gap Identified", notes

    # ── Strong positive signal can compensate moderate-only blockers ──
    if severe_count == 0 and positive_count >= 3 and moderate_count <= 2:
        # User clearly describes compliance — moderate-only notes are informational
        return current_status, notes

    # ── Multiple severe (≥2) → Gap ──
    if severe_count >= 2:
        return "Gap Identified", notes

    # ── One severe → Gap (if no strong positive) ──
    if severe_count == 1:
        # If there's 1 severe gap, we force a Gap status unless the positive signal is extremely strong (>4)
        if positive_count >= 5:
            return "Partially Implemented", notes
        return "Gap Identified", notes

    # ── Multiple moderate (≥2) without positive credit → Partial ──
    if moderate_count >= 2:
        return "Partially Implemented", notes

    # ── Single moderate → keep original with note ──
    return current_status, notes


# ═══════════════════════════════════════════════════════════════════════════
#  POLICY REFERENCE HELPER
# ═══════════════════════════════════════════════════════════════════════════

def ensure_policy_references_non_empty(
    refs: list[str],
    policy_chunks: list[str],
    max_quotes: int = 3,
    max_len: int = 350,
) -> list[str]:
    """Guarantee at least one verbatim excerpt from retrieved policy chunks."""
    cleaned = [r.strip() for r in refs if r and str(r).strip()]
    if cleaned:
        return cleaned[:max_quotes]

    out: list[str] = []
    for chunk in policy_chunks[:max_quotes]:
        excerpt = chunk.strip()
        if len(excerpt) > max_len:
            excerpt = excerpt[: max_len - 3] + "..."
        out.append(f'Policy excerpt: "{excerpt}"')

    if not out:
        out = ['Policy excerpt: "(retrieval unavailable)"']
    return out
