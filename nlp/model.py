from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Singleton — loaded once at startup, reused for every request.
_classifier = None
_load_failed = False


def load_model() -> None:
    """
    Load the DistilBERT text-classification pipeline into the module-level
    singleton.  Call this once during application startup (lifespan).
    Errors are caught so the server can still start with keyword fallback.
    """
    global _classifier, _load_failed
    if _classifier is not None:
        return

    try:
        from transformers import pipeline  # type: ignore

        logger.info("[NLP] Loading DistilBERT phishing classifier …")
        _classifier = pipeline(
            "text-classification",
            model="distilbert-base-uncased-finetuned-sst-2-english",
            truncation=True,
            max_length=512,
        )
        logger.info("[NLP] DistilBERT classifier ready.")
    except Exception as exc:  # noqa: BLE001
        _load_failed = True
        logger.warning("[NLP] Model load failed (%s) — keyword fallback active.", exc)


def get_classifier():
    """Return the loaded pipeline, or None if loading failed."""
    return _classifier
