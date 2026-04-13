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
Every input passes through a security firewall before reaching the AI:
- **Input Sanitization**: Prevents prompt injection attacks and malicious formatting.
- **Context Grounding**: The system prompt strictly limits the LLM's knowledge to the retrieved policy facts, effectively "muzzling" its general training data.

---

##  Technology Stack

| Component | Technology | Why? |
| :--- | :--- | :--- |
| **Backend** | Flask (Python) | Lightweight and highly extensible. |
| **LLM Engine** | Ollama (Llama 3.1) | Best-in-class local performance with 100% privacy. |
| **Vector Index** | FAISS | Industrial-grade search performance. |
| **PDF Extraction** | pypdf | Reliable, local PDF parsing. |
| **Frontend** | Vanilla JS / CSS | High-performance, dependency-free SaaS Light interface. |

---

##  Features

- **Interactive Wizard**: A step-by-step guided interface for policy upload and control assessment.
- **Real-time Feedback**: Live character counters and progress indicators during analysis.
- **Visual Dashboard**: Interactive charts and color-coded status indicators for quick comprehension.
- **Professional Export**: Generates a high-quality, print-ready PDF report suitable for audits and stakeholder presentations.
- **Privacy-First**: All processing occurs locally. No data leaves your machine.

## Future scope
## 🔮 Future Scope

- **Deployment**: Dockerization for one-click setup and Multi-User session support.
- **Enhanced AI**: Multi-policy comparison (e.g., ISO vs. SOC2) and AI confidence scoring.
- **Integrations**: Automated ticketing (JIRA/ServiceNow) for identified gaps and email reports.
- **Analytics**: Historical compliance tracking and high-level executive dashboards.
- **Extended Support**: Fine-tuned security-specific models and multi-language policy parsing.
- **user account login/signup with JWT authentication** : authentication and authorization for multi-user support.



