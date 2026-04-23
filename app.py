import os
import json
import hashlib
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from pypdf import PdfReader

from src.assessor import assess_controls, compute_compliance_summary, CONTROL_AREAS
from src.guardrail import MAX_INPUT_LENGTH
from src.index import ensure_index


load_dotenv()   

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
POLICY_PDF_PATH = Path(
    os.getenv("POLICY_PDF_PATH", str(APP_DIR / "policy" / "security-control-policy.pdf"))
)

app = Flask(__name__, static_folder="static", template_folder="templates")


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/assess")
def assess():
    try:
        
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            descriptions = payload.get("descriptions") or {}
        else:
            descriptions_str = request.form.get("descriptions", "{}")
            descriptions = json.loads(descriptions_str)

        
        policy_file = request.files.get("policy_file")
        active_pdf_path = POLICY_PDF_PATH
        active_data_dir = DATA_DIR

        if policy_file and policy_file.filename:
            file_bytes = policy_file.read()
            if len(file_bytes) > 0:
                
                file_hash = hashlib.md5(file_bytes).hexdigest()
                hash_dir = DATA_DIR / "custom_hashes" / file_hash
                hash_dir.mkdir(parents=True, exist_ok=True)
                
                
                active_pdf_path = hash_dir / "custom_policy.pdf"
                if not active_pdf_path.exists():
                    active_pdf_path.write_bytes(file_bytes)
                
                
                active_data_dir = hash_dir

        # ── Input validation ──
        errors: list[str] = []
        for area, desc in descriptions.items():
            if isinstance(desc, str) and len(desc) > MAX_INPUT_LENGTH:
                errors.append(
                    f"{area}: input too long ({len(desc)} chars, max {MAX_INPUT_LENGTH})"
                )
        if errors:
            return jsonify({"error": "; ".join(errors), "results": {}}), 400

        ensure_index(policy_pdf_path=active_pdf_path, data_dir=active_data_dir)
        results = assess_controls(descriptions=descriptions, data_dir=active_data_dir)
        summary = compute_compliance_summary(results)

        return jsonify({"results": results, "summary": summary})

    except Exception as e:
        return jsonify({"error": str(e), "results": {}}), 500


# ── BRD Extraction prompt ─────────────────────────────────────────────────────
_BRD_EXTRACT_PROMPT = """\
You are a cybersecurity analyst. You will be given the full text of a BRD (Business Requirements Document),
architecture document, or security design document. Your job is to extract ONLY factual implementation
details that are explicitly stated in the document for each of the seven security control areas listed below.

For each control area, extract a concise paragraph (2-5 sentences) describing how the system implements
that control, using ONLY information found in the document. If the document does not contain enough
information about a specific control area, return null for that area.

Do NOT invent, assume, or infer information that is not explicitly stated.
Do NOT copy generic boilerplate — only extract concrete, document-specific details.

Control areas to extract:
1. Authorization
2. Authentication
3. Logging & Monitoring
4. Certification & Compliance
5. Application Patching
6. System Hardening
7. Session Management

Respond with ONLY a JSON object in this exact format:
{
  "Authorization": "<extracted text or null>",
  "Authentication": "<extracted text or null>",
  "Logging & Monitoring": "<extracted text or null>",
  "Certification & Compliance": "<extracted text or null>",
  "Application Patching": "<extracted text or null>",
  "System Hardening": "<extracted text or null>",
  "Session Management": "<extracted text or null>"
}
"""


@app.post("/extract-brd")
def extract_brd():
    """Accept a BRD/architecture PDF and extract security details per control area."""
    try:
        brd_file = request.files.get("brd_file")
        if not brd_file or not brd_file.filename:
            return jsonify({"error": "No BRD file provided.", "extractions": {}}), 400

        file_bytes = brd_file.read()
        if len(file_bytes) == 0:
            return jsonify({"error": "Uploaded file is empty.", "extractions": {}}), 400

        # Extract text from the PDF
        import io
        reader = PdfReader(io.BytesIO(file_bytes))
        pages_text = []
        for page in reader.pages:
            pages_text.append(page.extract_text() or "")
        full_text = "\n".join(pages_text).strip()

        if not full_text:
            return jsonify({"error": "Could not extract text from the PDF. Please ensure it is not a scanned image.", "extractions": {}}), 400

        # Truncate to avoid overly large context (keep first ~12,000 chars)
        truncated_text = full_text[:12000]
        if len(full_text) > 12000:
            truncated_text += "\n\n[Document truncated for processing...]"

        from src.llm import chat_json, LLMError
        user_prompt = f"DOCUMENT TEXT:\n\n{truncated_text}"

        try:
            obj = chat_json([
                {"role": "system", "content": _BRD_EXTRACT_PROMPT},
                {"role": "user", "content": user_prompt},
            ])
        except LLMError as e:
            return jsonify({"error": f"LLM extraction failed: {str(e)}", "extractions": {}}), 500

        # Normalize: ensure all 7 areas are present, clean up values
        extractions = {}
        for area in CONTROL_AREAS:
            val = obj.get(area)
            if val and isinstance(val, str) and val.strip() and val.strip().lower() not in {"null", "none", "n/a", ""}:
                extractions[area] = val.strip()
            else:
                extractions[area] = None

        found_count = sum(1 for v in extractions.values() if v is not None)
        return jsonify({
            "extractions": extractions,
            "found_count": found_count,
            "total": len(CONTROL_AREAS),
        })

    except Exception as e:
        return jsonify({"error": str(e), "extractions": {}}), 500


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        debug=True,
    )
