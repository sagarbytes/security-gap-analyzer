import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from src.assessor import assess_controls, compute_compliance_summary
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
        payload = request.get_json(silent=True) or {}
        descriptions = payload.get("descriptions") or {}

        # ── Input validation ──
        errors: list[str] = []
        for area, desc in descriptions.items():
            if isinstance(desc, str) and len(desc) > MAX_INPUT_LENGTH:
                errors.append(
                    f"{area}: input too long ({len(desc)} chars, max {MAX_INPUT_LENGTH})"
                )
        if errors:
            return jsonify({"error": "; ".join(errors), "results": {}}), 400

        ensure_index(policy_pdf_path=POLICY_PDF_PATH, data_dir=DATA_DIR)
        results = assess_controls(descriptions=descriptions, data_dir=DATA_DIR)
        summary = compute_compliance_summary(results)

        return jsonify({"results": results, "summary": summary})

    except Exception as e:
        return jsonify({"error": str(e), "results": {}}), 500


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        debug=True,
    )
