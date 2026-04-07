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
DYNAMIC POLICY EVALUATION
════════════════════════════════════════════
• ALL rules and limits MUST be sourced dynamically from the provided POLICY EXCERPTS. Do not assume industry defaults; rely exclusively on the text provided.
• SEMANTIC TIMEFRAME MAPPING: You must actively comprehend natural language buzzwords in the user description. For example, if a user states "we deploy patches in a couple of days", evaluate that semantically as equivalent to "~48 hours" when comparing it against quantitative SLA limits defined in the policy.
• Translate vague descriptors ("a few months", "nearly immediately") into realistic numeric timelines to cross-check compliance cleanly.
• CHAIN OF THOUGHT: Mentally identify the explicit limits in the policy. If the user says they use a method that the policy explicitly forbids (e.g. policy says "RBAC is forbidden", user says "we use RBAC"), you MUST instantly classify as 'Gap Identified'.

════════════════════════════════════════════
CLASSIFICATION RULES
════════════════════════════════════════════
• "Compliant" → the description satisfies ALL applicable requirements.
• "Partially Implemented" → some requirements met but clear gaps remain.
• "Gap Identified" → major requirements are missing, contradicted, or the input is meaningless.

If the user description is gibberish, meaningless (e.g. "something", "test", "N/A", "dddd"), or completely unrelated to cybersecurity policy, you MUST return "Gap Identified" and state "Input lacks sufficient meaningful detail."

IMPORTANT GUIDELINES:
1. Do NOT assume compliance without evidence in the user description.
2. Do NOT over-penalize: if the description covers MOST requirements, prefer "Compliant".
   Only mark "Partially Implemented" when specific gaps are evident.
3. Minor omissions of optional/secondary details → still "Compliant" if core requirements met.
4. Explicit contradictions of policy (e.g., "no MFA", "30-day retention") → downgrade.
5. Treat vague, extremely short, or severely misspelled garbled text strictly as a Gap Identified.
6. Always cite 1–2 SHORT quotes from the policy excerpts in policy_reference.

════════════════════════════════════════════
OUTPUT FORMAT — strict JSON, nothing else
════════════════════════════════════════════
{
  "control_area": "<area name>",
  "status": "Compliant" | "Partially Implemented" | "Gap Identified",
  "summary": "<1-2 sentence assessment>",
  "gap_detail": "<specific gaps found, or null if Compliant>",
  "policy_reference": ["<short policy quote 1>", "<short policy quote 2>"]
}

Do NOT include any text outside the JSON object. Do NOT wrap in markdown fences.
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