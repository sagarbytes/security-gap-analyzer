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
#  BLOCKER RULES  (detect policy violations → may downgrade status)
# ═══════════════════════════════════════════════════════════════════════════


def _blockers_authentication(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # MFA missing entirely
    if re.search(
        r"\bno\s+mfa\b|\bmfa\s+not\b|without\s+mfa|password\s+only|single[- ]factor",
        t,
    ):
        out.append((
            "Policy requires MFA for all users; description indicates MFA is not in place.",
            "severe",
        ))
    # MFA not universal
    elif re.search(
        r"mfa.*\b(optional|opt-in|only\s+for\s+admins?|admins?\s+only|not\s+for\s+all|not\s+mandatory)\b",
        t,
    ) or re.search(r"\b(optional|admins?\s+only).{0,80}\bmfa\b", t):
        out.append((
            "Policy requires MFA mandatory for all users; description suggests MFA is not universal.",
            "severe",
        ))

    # Weak password length
    if re.search(r"\b(8|9|10)\s*(char|charact|digit)", t) and not re.search(
        r"1[2-9]\s*(char|charact)|at\s+least\s+1[2-9]|≥\s*12|greater\s+than\s+1[1-9]",
        t,
    ):
        out.append((
            "Policy requires password length ≥ 12 with complexity; description suggests weaker rules.",
            "severe",
        ))

    # Default credentials not addressed
    if "default" in t and re.search(
        r"default\s+(password|cred|login)|leave\s+default|vendor\s+default", t
    ):
        out.append((
            "Policy requires default credentials removed/changed before deployment.",
            "moderate",
        ))

    # SSO not mentioned at all (moderate — not severe since SSO is "where supported")
    if "sso" not in t and "single sign" not in t:
        out.append((
            "Policy requires SSO where supported; not mentioned in description.",
            "moderate",
        ))

    return out


def _blockers_logging(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Retention too short
    if re.search(r"\b(30|60|90)\s*days?\b|\b6\s*months?\b", t) and not re.search(
        r"1\s*year|365\s*days?|at\s+least\s+a\s+year|minimum\s+one\s+year|≥\s*1\s*year",
        t,
    ):
        out.append((
            "Policy requires log retention ≥ 1 year; description suggests shorter retention.",
            "severe",
        ))

    # No SIEM
    if re.search(
        r"only\s+when\s+troubleshoot|no\s+siem|not\s+.*\bsiem\b|local\s+files?\s+only",
        t,
    ):
        out.append((
            "Policy requires logs sent to central SIEM and weekly review.",
            "moderate",
        ))

    # NTP / time sync not mentioned
    if "ntp" not in t and "time sync" not in t and "time synchroniz" not in t:
        out.append((
            "Policy requires NTP / time synchronization across all systems; not mentioned.",
            "moderate",
        ))

    return out


def _blockers_session(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Timeout too long
    if re.search(r"\b(30|45|60|90|120)\s*(min|minutes?|mins?)\b", t) and not re.search(
        r"\b15\s*(min|minutes?)\b.*\b(privileged|admin)|privileged.{0,40}5\s*(min|minutes?)",
        t,
    ):
        if "15" not in t and "5" not in t:
            out.append((
                "Policy requires 15 min (users) / 5 min (privileged) inactivity timeouts.",
                "severe",
            ))

    # Insecure token storage
    if "localstorage" in t or "local storage" in t:
        out.append((
            "Policy requires session tokens encrypted and invalidated on logout; "
            "browser localStorage is high risk.",
            "moderate",
        ))

    # Predictable session IDs (but not "non-predictable" or "unpredictable")
    if re.search(r"(?<!non[- ])(?<!un)predictable\s+session|sequential\s+(session|id|token)", t):
        out.append((
            "Policy requires non-predictable session IDs.",
            "severe",
        ))

    # Simultaneous logins allowed with no restriction
    if re.search(r"allow.{0,30}simultaneous|no.{0,20}concurrent.{0,20}limit", t):
        out.append((
            "Policy requires prevention of simultaneous logins where possible.",
            "moderate",
        ))

    return out


def _blockers_patching(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Critical patches too slow
    if re.search(
        r"critical.{0,100}(week|month|two\s*weeks?|14\s*days?|21\s*days?)", t
    ):
        out.append((
            "Policy requires critical patches within 48 hours; description suggests slower handling.",
            "severe",
        ))

    # Legacy/unsupported without compensating controls
    if re.search(r"legacy|unsupported|end of life|eol", t) and not re.search(
        r"compensat|documented|risk\s+accept", t
    ):
        out.append((
            "Policy requires compensating controls documented for legacy/unsupported systems.",
            "moderate",
        ))

    # No formal patch lifecycle mentioned
    if re.search(r"no\s+formal|ad\s*hoc\s+patch|manual.{0,30}patch", t):
        out.append((
            "Policy requires a formal patch management lifecycle.",
            "moderate",
        ))

    return out


def _blockers_authorization(desc: str) -> list[tuple[str, Severity]]:
    t = _lower(desc)
    out: list[tuple[str, Severity]] = []

    # Access review cadence too weak
    if re.search(
        r"(annual|yearly|two\s*years?|never|ad\s*hoc).{0,40}(review|access\s*review)",
        t,
    ) or re.search(r"access\s*review.{0,40}(annual|two\s*years?|never)", t):
        out.append((
            "Policy requires access review at least quarterly; description suggests weaker cadence.",
            "moderate",
        ))

    # Privileged accounts not reviewed
    if re.search(
        r"privileged.{0,80}(not\s+review|no\s+schedule|only\s+incident)", t
    ):
        out.append((
            "Policy requires privileged accounts monitored/reviewed monthly.",
            "moderate",
        ))

    # No RBAC or PoLP mentioned
    if "rbac" not in t and "role" not in t and "least privilege" not in t:
        out.append((
            "Policy requires RBAC and Principle of Least Privilege; not clearly mentioned.",
            "moderate",
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

    # Weak transport encryption
    if re.search(r"plain\s*http|no\s*tls|tls\s*1\.[01]\b", t):
        out.append((
            "Policy requires TLS 1.2+ for data in transit; description suggests weaker transport.",
            "severe",
        ))

    # No CIS / baseline
    if re.search(r"vendor\s+default|no\s+cis|not\s+cis", t):
        out.append((
            "Policy references secure configuration baselines (CIS); not demonstrated.",
            "moderate",
        ))

    # Admin interfaces not segregated
    if re.search(r"admin.{0,40}(public|open|internet|unsegregated|not\s+restrict)", t):
        out.append((
            "Policy requires administrative interfaces segregated and restricted.",
            "moderate",
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
    blockers = get_rule_blockers(control_area, description)
    positive_count = _count_positive_matches(control_area, description)

    if not blockers:
        return current_status, []

    severe_count = sum(1 for _, s in blockers if s == "severe")
    moderate_count = sum(1 for _, s in blockers if s == "moderate")
    notes = [b[0] for b in blockers]

    # ── Strong positive signal can compensate moderate-only blockers ──
    if severe_count == 0 and positive_count >= 3 and moderate_count <= 2:
        # User clearly describes compliance — moderate-only notes are informational
        return current_status, notes

    # ── Multiple severe → Gap ──
    if severe_count >= 2:
        return "Gap Identified", notes

    # ── One severe → Partial ──
    if severe_count == 1:
        # But if strong positive signal, keep as partial (don't go to gap)
        return "Partially Implemented", notes

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
