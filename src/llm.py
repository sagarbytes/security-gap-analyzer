"""
LLM integrations — Ollama (local) and OpenAI backends.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

import requests


class LLMError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Ollama backend
# ---------------------------------------------------------------------------
def _ollama_chat(messages: list[dict[str, str]]) -> str:
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3:latest")
    url = f"{base}/api/chat"
    resp = requests.post(
        url,
        json={
            "model": model,
            "messages": messages,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_ctx": 4096},
        },
        timeout=180,
    )
    if not resp.ok:
        raise LLMError(f"Ollama error: {resp.status_code} {resp.text[:500]}")
    data = resp.json()
    return (data.get("message") or {}).get("content") or ""


# ---------------------------------------------------------------------------
# OpenAI backend
# ---------------------------------------------------------------------------
def _openai_chat(messages: list[dict[str, str]]) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise LLMError("OPENAI_API_KEY is not set and USE_OLLAMA is not enabled.")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    url = "https://api.openai.com/v1/chat/completions"
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        },
        timeout=180,
    )
    if not resp.ok:
        raise LLMError(f"OpenAI error: {resp.status_code} {resp.text[:500]}")
    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        raise LLMError(f"Unexpected OpenAI response shape: {e}")


# ---------------------------------------------------------------------------
# JSON cleaning helpers
# ---------------------------------------------------------------------------
_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


def _clean_json_string(raw: str) -> str:
    """Strip markdown fences, BOM, trailing commas, and whitespace."""
    s = raw.strip()
    # Remove UTF-8 BOM
    s = s.lstrip("\ufeff")

    # Extract from code fences if present
    fence_match = _CODE_FENCE_RE.search(s)
    if fence_match:
        s = fence_match.group(1).strip()

    # Remove trailing commas before } or ]
    s = _TRAILING_COMMA_RE.sub(r"\1", s)
    return s


def _try_parse_json(raw: str) -> dict[str, Any] | None:
    """Attempt to parse raw text as JSON, with cleaning."""
    cleaned = _clean_json_string(raw)
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        pass

    # Last resort: find the outermost { ... }
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(cleaned[start: end + 1])
        except (json.JSONDecodeError, ValueError):
            pass

    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def chat_json(messages: list[dict[str, str]], _retried: bool = False) -> dict[str, Any]:
    """Send messages to the configured LLM and return parsed JSON."""
    use_ollama = os.getenv("USE_OLLAMA", "1").lower() in {"1", "true", "yes", "y"}
    raw = _ollama_chat(messages) if use_ollama else _openai_chat(messages)

    result = _try_parse_json(raw)
    if result is not None:
        return result

    # Retry once with a nudge
    if not _retried:
        retry_messages = messages + [
            {"role": "assistant", "content": raw},
            {
                "role": "user",
                "content": (
                    "Your previous response was not valid JSON. "
                    "Please respond with ONLY a JSON object, no extra text."
                ),
            },
        ]
        return chat_json(retry_messages, _retried=True)

    raise LLMError(f"Model did not return valid JSON after retry. Raw: {raw[:600]}")
