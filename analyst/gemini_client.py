from __future__ import annotations

import os
from typing import Optional

try:
    from google import genai
    from google.genai import types as genai_types
    _GENAI_AVAILABLE = True
except Exception:
    genai = None
    genai_types = None
    _GENAI_AVAILABLE = False


class GeminiClient:
    def __init__(self, model_name: str | None = None) -> None:
        preferred = str(model_name or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")).strip()
        fallbacks = [preferred, "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]

        deduped: list[str] = []
        for name in fallbacks:
            if not name or name in deduped:
                continue
            deduped.append(name)

        self.model_candidates = deduped
        self.model_name = self.model_candidates[0]
        self._client: object | None = None

    def _ensure_client(self) -> None:
        if self._client is not None:
            return
        if not _GENAI_AVAILABLE:
            raise RuntimeError("google-genai package is not installed")

        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not set")

        self._client = genai.Client(api_key=api_key)

    def generate_analysis(self, prompt: str) -> str:
        self._ensure_client()
        errors: list[str] = []

        for model_name in self.model_candidates:
            try:
                response = self._client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )
                text = self._extract_text(response)
                if text:
                    self.model_name = model_name
                    return text
                errors.append(f"{model_name}: empty_response")
            except Exception as exc:
                detail = str(exc).replace("\n", " ").strip()
                if len(detail) > 180:
                    detail = f"{detail[:177]}..."
                errors.append(f"{model_name}: {type(exc).__name__} ({detail})" if detail else f"{model_name}: {type(exc).__name__}")

        detail = "; ".join(errors) if errors else "unknown_error"
        raise RuntimeError(f"Gemini model invocation failed ({detail})")

    @staticmethod
    def _extract_text(response: object) -> str:
        # New SDK: response.text is the primary accessor
        text: Optional[str] = getattr(response, "text", None)
        if text and text.strip():
            return text.strip()

        # Fallback: iterate candidates → content → parts
        candidates = getattr(response, "candidates", [])
        for candidate in (candidates or []):
            content = getattr(candidate, "content", None)
            if not content:
                continue
            parts = getattr(content, "parts", [])
            for part in (parts or []):
                part_text = getattr(part, "text", "")
                if part_text:
                    return part_text.strip()

        return ""
