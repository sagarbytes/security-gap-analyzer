import json
import re
from dataclasses import dataclass
from pathlib import Path

import faiss
import numpy as np
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer


EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"




_model_cache: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model_cache
    if _model_cache is None:
        _model_cache = SentenceTransformer(EMBED_MODEL_NAME)
    return _model_cache


@dataclass(frozen=True)
class Chunk:
    id: str
    text: str



# PDF reading

def _read_pdf_text(pdf_path: Path) -> str:
    reader = PdfReader(str(pdf_path))
    parts: list[str] = []
    for page in reader.pages:
        parts.append(page.extract_text() or "")
    return "\n".join(parts).strip()


def _normalize_whitespace(s: str) -> str:
    return " ".join((s or "").split())





_SECTION_RE = re.compile(
    r"(4\.\d+)\s+(.*?)(?=\n|$)", re.IGNORECASE
)

SECTION_TITLES: dict[str, str] = {
    "4.1": "Authorization Policy",
    "4.2": "Authentication Policy",
    "4.3": "Logging & Monitoring Policy",
    "4.4": "Certification & Compliance Policy",
    "4.5": "Application Patching Policy",
    "4.6": "System Hardening Policy",
    "4.7": "Session Management Policy",
}


def _split_by_sections(text: str) -> list[tuple[str, str]]:
    """Split policy text into (section_header, section_body) pairs."""
    
    matches = list(_SECTION_RE.finditer(text))

    if not matches:
        
        return [("Policy", text)]

    sections: list[tuple[str, str]] = []

    for i, m in enumerate(matches):
        section_num = m.group(1)
        header = SECTION_TITLES.get(section_num, m.group(2).strip())
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        sections.append((f"{section_num} {header}", body))

    return sections


def _chunk_section(
    section_header: str,
    section_body: str,
    max_chars: int = 500,
    overlap: int = 80,
) -> list[str]:
    """Chunk a single section's body into overlapping pieces, prefixed with header."""
    clean = section_body.replace("\r", "\n")
    paragraphs = [p.strip() for p in clean.split("\n") if p.strip()]

    raw_chunks: list[str] = []
    buf: list[str] = []
    buf_len = 0

    def flush():
        nonlocal buf, buf_len
        if not buf:
            return
        joined = _normalize_whitespace("\n".join(buf))
        raw_chunks.append(joined)
        if overlap > 0 and joined:
            tail = joined[-overlap:]
            buf = [tail]
            buf_len = len(tail)
        else:
            buf = []
            buf_len = 0

    for p in paragraphs:
        if buf_len + len(p) + 1 > max_chars:
            flush()
        buf.append(p)
        buf_len += len(p) + 1
    flush()

    
    return [f"[{section_header}] {chunk}" for chunk in raw_chunks]


def _chunk_policy_text(text: str, max_chars: int = 500, overlap: int = 80) -> list[Chunk]:
    """Section-aware chunking: split by policy sections, then sub-chunk each."""
    sections = _split_by_sections(text)
    chunks: list[Chunk] = []
    i = 0

    for header, body in sections:
        sub_chunks = _chunk_section(header, body, max_chars=max_chars, overlap=overlap)
        for sc in sub_chunks:
            chunks.append(Chunk(id=f"chunk_{i}", text=sc))
            i += 1

    
    if not chunks:
        normalized = _normalize_whitespace(text)
        chunks.append(Chunk(id="chunk_0", text=normalized))

    return chunks





def build_index(policy_pdf_path: Path, data_dir: Path) -> None:
    if not policy_pdf_path.exists():
        raise FileNotFoundError(
            f"Policy PDF not found at {policy_pdf_path}. "
            "Set POLICY_PDF_PATH env var or place the file at policy/security-control-policy.pdf"
        )

    data_dir.mkdir(parents=True, exist_ok=True)
    index_path = data_dir / "index.faiss"
    chunks_path = data_dir / "chunks.json"

    text = _read_pdf_text(policy_pdf_path)
    chunks = _chunk_policy_text(text=text)
    model = _get_model()
    vectors = model.encode(
        [c.text for c in chunks], normalize_embeddings=True, show_progress_bar=False
    )
    vectors = np.asarray(vectors, dtype="float32")

    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(vectors)
    faiss.write_index(index, str(index_path))

    chunks_payload = [{"id": c.id, "text": c.text} for c in chunks]
    chunks_path.write_text(json.dumps(chunks_payload, indent=2), encoding="utf-8")


def ensure_index(policy_pdf_path: Path, data_dir: Path) -> None:
    index_path = data_dir / "index.faiss"
    chunks_path = data_dir / "chunks.json"

    needs_rebuild = False

    if not index_path.exists() or not chunks_path.exists():
        needs_rebuild = True
    elif policy_pdf_path.exists():
        
        pdf_mtime = policy_pdf_path.stat().st_mtime
        idx_mtime = index_path.stat().st_mtime
        if pdf_mtime > idx_mtime:
            needs_rebuild = True

    if needs_rebuild:
        build_index(policy_pdf_path=policy_pdf_path, data_dir=data_dir)


def load_index(data_dir: Path):
    index_path = data_dir / "index.faiss"
    chunks_path = data_dir / "chunks.json"
    if not index_path.exists() or not chunks_path.exists():
        raise FileNotFoundError("Index not built yet. Run ensure_index() first.")

    index = faiss.read_index(str(index_path))
    chunks_payload = json.loads(chunks_path.read_text(encoding="utf-8"))
    chunks = [Chunk(id=c["id"], text=c["text"]) for c in chunks_payload]
    return index, chunks


def retrieve_relevant(policy_query: str, data_dir: Path, k: int = 5) -> list[str]:
    index, chunks = load_index(data_dir=data_dir)
    model = _get_model()
    q = model.encode([policy_query], normalize_embeddings=True, show_progress_bar=False)
    q = np.asarray(q, dtype="float32")
    scores, ids = index.search(q, k)
    hit_ids = ids[0].tolist()
    out: list[str] = []
    for idx in hit_ids:
        if idx < 0 or idx >= len(chunks):
            continue
        out.append(chunks[idx].text)
    return out
