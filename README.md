# Security Control Gap Analysis (Policy‑Grounded)

This project implements the **AI Development Assessment Task**:
a single-page web app that collects user descriptions for **seven security control areas** and returns a **gap assessment** grounded strictly in the provided security policy PDF.

## What it does

- **Single web page** with exactly **7 required** text areas:
  - Authorization
  - Authentication
  - Logging & Monitoring
  - Certification & Compliance
  - Application Patching
  - System Hardening
  - Session Management
- **One backend POST endpoint**: `POST /assess`
- **Vector retrieval grounding**:
  - The policy PDF is embedded into a local FAISS vector index.
  - **Section-aware chunking**: the policy is split by section (4.1–4.7) producing one clean chunk per control area for highly precise retrieval.
  - For each control area, the backend retrieves the most relevant policy excerpts and provides them to the LLM.
  - The LLM is instructed to use **only those excerpts** for requirements and to return **structured JSON**.
- **Rule-based post-processing**:
  - A keyword/heuristic engine validates the LLM's output against known policy thresholds (e.g. 48h for critical patches, 12-char passwords, MFA mandatory).
  - **Positive keyword credit**: if the description matches key compliance phrases, false downgrades are prevented.
  - **Blocker detection**: explicit violations (e.g. "no MFA", "30-day retention") trigger downgrades.
- **Guardrails**:
  - System prompt fixes the model's role as a policy gap assessor and tells it to ignore instructions inside user input.
  - 20+ prompt-injection detection patterns (instruction overrides, role-play, system prompt extraction, encoding tricks, jailbreak prefixes).
  - Input length validation (max 3000 characters per field).
  - Visible error display in the results card when guardrails trigger.
- **Compliance summary**: overall score as percentage, breakdown of Compliant / Partially Implemented / Gap Identified.
- **Export**: download assessment results as JSON.

## Local setup

### 1) Put the policy PDF in place

Copy `security-control-policy.pdf` into:

- `policy/security-control-policy.pdf`

### 2) Create a virtual environment and install dependencies

```bash
cd "/Users/sagaryadav/Desktop/security-gap-analyzer"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3) Choose an LLM backend

This app supports:

- **Ollama (default)**: no API key required
  - Environment:
    - `USE_OLLAMA=1`
    - `OLLAMA_MODEL` (default: `llama3.1:8b`)
    - `OLLAMA_BASE_URL` (default: `http://localhost:11434`)
- **OpenAI**:
  - Environment:
    - `USE_OLLAMA=0`
    - `OPENAI_API_KEY=...`
    - `OPENAI_MODEL` (default: `gpt-4.1-mini`)

Create a `.env` file (do not commit it), example:

```bash
USE_OLLAMA=1
OLLAMA_MODEL=llama3.1:8b
```

### 4) Run the app

```bash
python app.py
```

Then open `http://127.0.0.1:8000`.

## Architecture (high level)

- **Front-end**: `templates/index.html` + `static/app.js` + `static/styles.css`
  - Single page UI with Inter font and premium dark theme
  - Character counters per field (max 3000 chars)
  - Submits all seven descriptions to `POST /assess`
  - Renders compliance summary (score ring + breakdown)
  - Renders seven result cards (status/summary/gap detail/policy references)
  - Export results as JSON
- **Back-end**: `app.py` (Flask)
  - Serves the single page and static assets
  - Handles `POST /assess` with input validation
  - Auto-rebuilds the FAISS index when the policy PDF changes
- **Vector store**: FAISS
  - Section-aware chunking: splits policy by section headers (4.1–4.7)
  - Each chunk is prefixed with its section header for retrieval context
  - Embeddings: `sentence-transformers/all-MiniLM-L6-v2` (cached at module level)
  - Retrieval uses cosine similarity (inner product over normalized vectors)
- **LLM assessment**: `src/assessor.py` + `src/llm.py`
  - Enhanced system prompt with explicit policy thresholds
  - Robust JSON parsing with code fence stripping, trailing comma handling, and auto-retry
  - For each control area: retrieve policy excerpts, then ask the LLM to compare description vs policy and return strict JSON:
    - `status`: `Compliant` / `Partially Implemented` / `Gap Identified`
    - `summary`
    - `gap_detail` (null when compliant)
    - `policy_reference` (verbatim quotes from retrieved policy excerpts)
- **Rule engine**: `src/policy_rules.py`
  - Blocker detection: regex-based checks for policy violations
  - Positive keyword credit: prevents false downgrades when key compliance phrases are present
  - Balanced downgrade logic considering both blockers and positive signals
- **Guardrails**: `src/guardrail.py`
  - 20+ prompt-injection patterns
  - Input length validation
  - Base64 payload detection

## Guardrail approach

- **System prompt**: defines the model as a **security policy assessor**, embeds key policy thresholds, forbids using general knowledge, and requires JSON-only output.
- **Prompt injection detection**: `src/guardrail.py` checks for 20+ attack patterns including instruction overrides, role-play, system prompt extraction, jailbreak prefixes, and encoding tricks.
- **Input length limit**: 3000 characters per field; rejected with clear error.
- **Visible behavior**: if triggered, the corresponding result card includes an **Error** field and the status is treated as **Gap Identified**.

## Policy embedding details

- **Chunking**: section-aware chunking that splits by policy section headers (4.1–4.7), producing ~7 chunks (one per control area), each prefixed with its section title
- **Embeddings**: `sentence-transformers/all-MiniLM-L6-v2` (cached for performance)
- **Persistence**: on first run, or when the policy PDF is newer than the index, the index is rebuilt automatically.
- Optional manual build:

```bash
python ingest_policy.py
```
