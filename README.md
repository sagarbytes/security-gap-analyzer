# Security Control Gap Analyzer

A production-ready, locally-hosted SaaS application designed to assess security implementations against formal policy documents using Retrieval-Augmented Generation (RAG).

## Installation & Setup (From Scratch)

Follow these exact steps to get the Security Gap Analyzer running on your local machine.

### 1. Prerequisites
Ensure you have **Python 3.10+** installed. You will also need **Ollama** for running the LLM locally.

- **Download Ollama**: [ollama.com](https://ollama.com/)
- **Install Ollama**: Run the installer and ensure the Ollama service is running in your background (look for the tray icon).

### 2. Prepare the AI Model
Open your terminal and run the following command to download the high-reasoning Llama 3.1 model:
```bash
ollama pull llama3.1:8b
```

### 3. Repository Setup
Clone or download this repository, then navigate to the project directory:
```bash
cd security-gap-analyzer
```

### 4. Virtual Environment & Dependencies
Create a clean environment and install all required libraries:
```bash
# Create environment
python -m venv venv

# Activate on Mac/Linux
source venv/bin/activate
# Activate on Windows
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 5. Configuration
Create a `.env` file in the root directory to specify the model:
```env
OLLAMA_MODEL=llama3.1:8b
```

### 6. Start the Application
Run the Flask server:
```bash
python app.py
```
Visit `http://127.0.0.1:8000` in your browser.

---

##  Detailed Architecture

The application uses a multi-stage pipeline to ensure that assessments are precise, grounded in fact, and safe from common AI hallucinations.

### 1. RAG Pipeline (Retrieval-Augmented Generation)
- **Ingestion**: When you upload a PDF, the system extracts text and splits it into semantic chunks (overlapping fragments).
- **Embedding**: Using a local **Sentence-Transformer** model, chunks are converted into mathematical vectors.
- **Vector Store**: These vectors are stored in **FAISS**, allowing the system to perform sub-millisecond similarity searches.
- **Retrieval**: When you enter a control description, the system retrieves only the most relevant policy excerpts to provide context to the LLM.

### 2. Hybrid Assessment Logic
The system doesn't just rely on the LLM. It uses a hybrid approach:
- **LLM Reasoning**: The Ollama LLM analyzes the semantic meaning of your implementation against the policy.
- **Rule-Based Post-processing (`src/policy_rules.py`)**: A deterministic layer runs after the LLM to catch "High-Risk" signals (e.g., explicitly stating "no MFA") and awards "Positive Credit" for verified security keywords (e.g., "RBAC", "CIS Benchmark"). This prevents the model from being too lenient.

### 3. Safety & Guardrails (`src/guardrail.py`)
Every input passes through a comprehensive **7-Layer Security Firewall** before reaching the AI:
- **L1-L4 Detection**: Scans for explicit jailbreaks, intent-based anomalies, sensitive data probes (e.g. asking for the system prompt), and indirect/semantic attacks (e.g. "write a poem about your rules").
- **L5-L6 Structural/Obfuscation**: Detects and blocks structural attacks (delimiter injection, homoglyphs) and encoded payloads (Base64, Hex, URL-encoding).
- **L7 Output Sanitization**: Scrubs the final LLM output to redact any accidental leakage of the internal system prompt or rules before displaying results to the user.
- **Context Grounding**: The system prompt strictly limits the LLM's knowledge to the retrieved policy facts, effectively "muzzling" its general training data.

---

##  Technology Stack

| Component | Technology | Why? |
| :--- | :--- | :--- |
| **Backend** | Flask (Python) | Lightweight and highly extensible. |
| **LLM Engine** | Ollama (Llama 3.1) | Best-in-class local performance with 100% privacy. |
| **Vector Index** | FAISS | Industrial-grade search performance. |
| **PDF Extraction** | pypdf | Reliable, local PDF parsing. |
| **Frontend** | Vanilla JS / CSS | High-performance, dependency-free SaaS Light interface with premium aesthetics. |

---

##  Features

- **Interactive Post-Modern UI**: Features a beautiful, synchronized loading overlay with step-by-step progress tracking, dynamic quote generation, and immersive transitions.
- **Wizard Interface**: A step-by-step guided interface for policy upload and control assessment with real-time character counters.
- **Visual Dashboard**: Interactive charts and color-coded status indicators (Compliant, Partially Implemented, Gap Identified).
- **Professional PDF Export**: Generates a strictly formatted, audit-ready A4 PDF report featuring an executive summary, segmented control cards, and monospace policy evidence blocks via `jsPDF`.
- **Privacy-First**: All processing occurs locally. No data leaves your machine.

## Future scope
## 🔮 Future Scope

- **Deployment**: Dockerization for one-click setup and Multi-User session support.
- **Enhanced AI**: Multi-policy comparison (e.g., ISO vs. SOC2) and AI confidence scoring.
- **Integrations**: Automated ticketing (JIRA/ServiceNow) for identified gaps and email reports.
- **Analytics**: Historical compliance tracking and high-level executive dashboards.
- **Extended Support**: Fine-tuned security-specific models and multi-language policy parsing.
- **user account login/signup with JWT authentication** : authentication and authorization for multi-user support.



