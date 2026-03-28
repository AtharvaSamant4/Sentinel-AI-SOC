"""
analyst/gemini_client.py
------------------------
Groq AI client for SENTINEL AI-SOC (via OpenAI-compatible API).

Environment variables:
  GROK_API_KEY – Groq API key
"""

from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)

from openai import OpenAI

_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 2.0

_GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
]


def _is_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "resource_exhausted" in msg or "rate" in msg


class GeminiClient:
    def __init__(self, model_name: str | None = None) -> None:
        api_key = os.getenv("GROK_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("GROK_API_KEY is not set in .env")

        self._client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
        )
        self.model_name = _GROQ_MODELS[0]
        logger.info("[ai] Groq client initialized")

    def generate_analysis(self, prompt: str) -> str:
        errors: list[str] = []

        for model in _GROQ_MODELS:
            for attempt in range(_MAX_RETRIES + 1):
                try:
                    response = self._client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": "You are a senior SOC analyst at SENTINEL AI-SOC. Respond in plain text only, no markdown."},
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.3,
                        max_tokens=1024,
                    )
                    text = (response.choices[0].message.content or "").strip()
                    if text:
                        self.model_name = model
                        return text
                    errors.append(f"{model}: empty_response")
                    break
                except Exception as exc:
                    if _is_rate_limit_error(exc) and attempt < _MAX_RETRIES:
                        wait = _BASE_BACKOFF_SECONDS * (2 ** attempt)
                        logger.warning(
                            "[ai] Groq 429 on %s (attempt %d/%d), retrying in %.1fs",
                            model, attempt + 1, _MAX_RETRIES, wait,
                        )
                        time.sleep(wait)
                        continue

                    detail = str(exc).replace("\n", " ").strip()
                    if len(detail) > 180:
                        detail = f"{detail[:177]}..."
                    errors.append(f"{model}: {type(exc).__name__} ({detail})")
                    logger.warning("[ai] Groq %s failed: %s", model, detail)
                    break

        detail = "; ".join(errors) if errors else "unknown_error"
        raise RuntimeError(f"Groq model invocation failed ({detail})")
