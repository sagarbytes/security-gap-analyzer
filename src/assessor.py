"""
Security control gap assessor — orchestrates LLM-based policy gap analysis
with retrieval-augmented generation and rule-based post-processing.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from src.guardrail import detect_prompt_injection
from src.index import retrieve_relevant
from src.llm import LLMError, chat_json
from src.policy_rules import apply_rule_downgrade, ensure_policy_references_non_empty


CONTROL_AREAS = [
    "Authorization",
    "Authentication",
    "Logging & Monitoring",
    "Certification & Compliance",
    "Application Patching",
    "System Hardening",
    "Session Management",
]

Status = Literal["Compliant", "Partially Implemented", "Gap Identified"]


@dataclass
class Assessment:
    control_area: str
    status: Status
    summary: str
    gap_detail: str | None
    policy_reference: list[str]
    error: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT — includes explicit policy thresholds for precision
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """\
You are a cybersecurity policy auditor. Your ONLY job is to compare the USER DESCRIPTION
against the POLICY EXCERPTS provided below and determine compliance status.

════════════════════════════════════════════
STRICT POLICY ADHERENCE
════════════════════════════════════════════
• EXPLICIT CONTRADICTION = AUTOMATIC GAP: If the user description explicitly contradicts a policy requirement (e.g. 60m timeout vs 15m policy, OR MFA "only for admins" vs policy "required for all users"), you MUST mark status as "Gap Identified".
• DYNAMIC LIMITS: All rules and limits MUST be sourced from excerpts. Do not assume industry defaults.
• SECTION CITATION: You MUST include specific Section Numbers or Policy IDs (e.g. "Section 4.7").
• NO LENIENCY ON CORE CONTROLS: If a core requirement (MFA, Patching SLA, Encryption) is only partially addressed or uses manual/slow processes, it is a GAP IDENTIFIED, not partial.

════════════════════════════════════════════
CLASSIFICATION RULES
════════════════════════════════════════════
• "Compliant" → Satisfies ALL requirements.
• "Partially Implemented" → Most core requirements met, but non-critical gaps remain.
• "Gap Identified" → Failure to meet core requirements, explicit contradictions, or total lack of detail.

If the user description is gibberish, meaningless (e.g. "something", "test", "N/A", "dddd"), or completely unrelated to cybersecurity policy, you MUST return "Gap Identified" and state "Input lacks sufficient meaningful detail."

IMPORTANT GUIDELINES:
1. Do NOT assume compliance.
2. CITATION IS MANDATORY: You must cite 1–2 verbatim quotes including the section header/number.
3. Be strict on specific limits (Timeouts, Password length, Retention periods).
4. Treat "localStorage" for sensitive session tokens as a high-risk Gap if the policy mentions "secure storage" or "encryption".

════════════════════════════════════════════
OUTPUT FORMAT — strict JSON
════════════════════════════════════════════
{
  "control_area": "<area name>",
  "status": "Compliant" | "Partially Implemented" | "Gap Identified",
  "summary": "<1-2 sentence assessment>",
  "gap_detail": "<specific list of gaps found, or null if Compliant>",
  "policy_reference": ["<Section Header/Number>: <verbatim quote 1>", "<Section Header/Number>: <verbatim quote 2>"]
}
"""


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _is_blank_or_na(s: str) -> bool:
    t = (s or "").strip().lower()
    return not t or t in {"n/a", "na", "not applicable", "none", "no", "-", "—"}


def _normalize_llm_status(raw: Any) -> Status:
    if raw is None:
        return "Gap Identified"

    s = str(raw).strip().lower()

    if "compliant" in s and "not" not in s and "non" not in s:
        return "Compliant"
    if "partial" in s:
        return "Partially Implemented"
    if "gap" in s or "not compliant" in s or "non-compliant" in s:
        return "Gap Identified"

    return "Gap Identified"


def _pick_status(obj: dict[str, Any]) -> Any:
    for key in ("status", "Status", "assessment_status", "compliance_status"):
        if key in obj and obj[key] is not None:
            return obj[key]
    return None


def _coerce_assessment(area: str, obj: dict[str, Any]) -> Assessment:
    status = _normalize_llm_status(_pick_status(obj))

    # Summary
    summary = (
        obj.get("summary") or obj.get("Summary") or obj.get("description") or ""
    ).strip()
    if not summary:
        summary = "The system description was evaluated against policy requirements."

    # Gap detail
    gap_detail = (
        obj.get("gap_detail")
        or obj.get("GapDetail")
        or obj.get("gap_details")
        or obj.get("gaps")
    )

    if status == "Compliant":
        gap_detail = None
    else:
        if gap_detail:
            gap_detail = str(gap_detail).strip()
        else:
            gap_detail = "Some policy requirements are not fully satisfied."

    # Policy references
    refs = (
        obj.get("policy_reference")
        or obj.get("PolicyReference")
        or obj.get("policy_references")
        or []
    )
    if isinstance(refs, str):
        refs = [refs]
    if not isinstance(refs, list):
        refs = []
    refs = [str(r).strip() for r in refs if str(r).strip()]

    return Assessment(
        control_area=area,
        status=status,
        summary=summary,
        gap_detail=gap_detail,
        policy_reference=refs,
        error=None,
    )


# ═══════════════════════════════════════════════════════════════════════════
# POST-LLM FINALIZATION (rules + reference cleaning)
# ═══════════════════════════════════════════════════════════════════════════

def _finalize_with_rules_and_refs(
    area: str,
    description: str,
    assessment: Assessment,
    policy_chunks: list[str],
) -> Assessment:
    # ── Clean policy references ──
    refs = ensure_policy_references_non_empty(
        assessment.policy_reference, policy_chunks
    )
    clean_refs = []
    for r in refs:
        r = r.strip()
        if len(r) < 250:
            clean_refs.append(r)
    assessment.policy_reference = clean_refs[:2]

    # ── Apply rule engine ──
    new_status, rule_notes = apply_rule_downgrade(
        area, description, assessment.status
    )
    assessment.status = new_status

    # Add rule notes to gap_detail when status is not Compliant
    if rule_notes and assessment.status != "Compliant":
        extra = "Rule-based validation: " + " | ".join(rule_notes)
        if assessment.gap_detail:
            assessment.gap_detail += "\n\n" + extra
        else:
            assessment.gap_detail = extra

    # Ensure gap_detail consistency
    if assessment.status == "Compliant":
        assessment.gap_detail = None
    elif not assessment.gap_detail:
        assessment.gap_detail = "Some policy requirements are not fully satisfied."

    return assessment


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ASSESSMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def assess_one(control_area: str, description: str, data_dir: Path) -> Assessment:
    """Assess a single control area against the policy."""

    # ── Guardrail check ──
    injection = detect_prompt_injection(description)

    # ── Retrieve relevant policy chunks ──
    policy_chunks = retrieve_relevant(
        policy_query=f"{control_area} {description[:500]}",
        data_dir=data_dir,
        k=5,
    )

    if injection:
        refs = ensure_policy_references_non_empty([], policy_chunks)
        return Assessment(
            control_area=control_area,
            status="Gap Identified",
            summary=description[:200],
            gap_detail="Prompt injection detected — input was blocked.",
            policy_reference=refs,
            error=injection,
        )

    if _is_blank_or_na(description):
        refs = ensure_policy_references_non_empty([], policy_chunks)
        return Assessment(
            control_area=control_area,
            status="Gap Identified",
            summary="No implementation details provided.",
            gap_detail="This area was left blank or marked not applicable.",
            policy_reference=refs,
        )

    # ── Build LLM prompt ──
    policy_text = "\n\n---\n\n".join(policy_chunks)

    user_prompt = f"""\
CONTROL AREA: {control_area}

USER DESCRIPTION:
{description}

POLICY EXCERPTS:
{policy_text}
"""

    try:
        obj = chat_json([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ])

        assessment = _coerce_assessment(control_area, obj)

        return _finalize_with_rules_and_refs(
            control_area, description, assessment, policy_chunks
        )

    except LLMError as e:
        refs = ensure_policy_references_non_empty([], policy_chunks)
        return Assessment(
            control_area=control_area,
            status="Gap Identified",
            summary=description[:200],
            gap_detail="LLM call failed.",
            policy_reference=refs,
            error=str(e),
        )


def assess_controls(
    descriptions: dict[str, str], data_dir: Path
) -> dict[str, dict[str, Any]]:
    """Assess all seven control areas and return results dict."""
    results: dict[str, dict[str, Any]] = {}

    for area in CONTROL_AREAS:
        desc = descriptions.get(area, "")
        result = assess_one(area, desc, data_dir)
        results[area] = asdict(result)

    return results


def compute_compliance_summary(
    results: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Compute an overall compliance summary from assessment results."""
    total = len(CONTROL_AREAS)
    compliant = 0
    partial = 0
    gap = 0

    for area in CONTROL_AREAS:
        r = results.get(area, {})
        status = r.get("status", "Gap Identified")
        if status == "Compliant":
            compliant += 1
        elif status == "Partially Implemented":
            partial += 1
        else:
            gap += 1

    # Score: Compliant=100%, Partial=50%, Gap=0%
    score = round(((compliant * 100) + (partial * 50)) / total) if total else 0

    return {
        "total_areas": total,
        "compliant": compliant,
        "partially_implemented": partial,
        "gap_identified": gap,
        "compliance_score": score,
    }