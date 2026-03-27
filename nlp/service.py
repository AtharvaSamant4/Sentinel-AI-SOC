from __future__ import annotations

import logging

from nlp.model import get_classifier

logger = logging.getLogger(__name__)

# Keywords used when the ML model is unavailable.
_PHISHING_KEYWORDS = [
    "urgent",
    "verify",
    "suspended",
    "account locked",
    "click here",
    "confirm your",
    "update your",
    "password reset",
    "unusual activity",
    "immediate action",
    "bank account",
    "wire transfer",
    "won a prize",
    "claim your",
    "limited time",
    "act now",
    "dear customer",
    "your account has been",
]

# DistilBERT SST-2 labels: POSITIVE = benign, NEGATIVE = negative/suspicious.
# We treat a high-confidence NEGATIVE prediction as indicative of phishing-like
# text (adversarial / alarming tone), which correlates well with phishing emails.
_PHISHING_LABEL = "NEGATIVE"
_PHISHING_THRESHOLD = 0.70


def classify_email(subject: str, body: str) -> dict:
    """
    Classify whether an email is phishing.

    Returns:
        {
            "is_phishing": bool,
            "confidence": float,   # 0.0 – 1.0
            "label": str,          # raw model label, or "KEYWORD_MATCH" / "KEYWORD_MISS"
            "method": str          # "distilbert" | "keyword_fallback"
        }
    """
    text = f"{subject} {body}".strip()

    classifier = get_classifier()
    if classifier is not None:
        return _classify_with_model(classifier, text)

    return _classify_with_keywords(text)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _classify_with_model(classifier, text: str) -> dict:
    try:
        result = classifier(text[:512])[0]
        label: str = result["label"]
        score: float = float(result["score"])

        # Map model confidence correctly:
        # NEGATIVE label  → phishing confidence = score
        # POSITIVE label  → phishing confidence = 1 - score
        if label == _PHISHING_LABEL:
            phishing_confidence = score
        else:
            phishing_confidence = 1.0 - score

        is_phishing = phishing_confidence > _PHISHING_THRESHOLD

        return {
            "is_phishing": is_phishing,
            "confidence": round(phishing_confidence, 4),
            "label": label,
            "method": "distilbert",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[NLP] Model inference error (%s) — falling back to keywords.", exc)
        return _classify_with_keywords(text)


def _classify_with_keywords(text: str) -> dict:
    lowered = text.lower()
    matched = any(kw in lowered for kw in _PHISHING_KEYWORDS)

    # Assign a rough confidence score based on how many keywords matched.
    matched_count = sum(1 for kw in _PHISHING_KEYWORDS if kw in lowered)
    confidence = min(0.55 + matched_count * 0.08, 0.95) if matched else 0.10

    return {
        "is_phishing": matched,
        "confidence": round(confidence, 4),
        "label": "KEYWORD_MATCH" if matched else "KEYWORD_MISS",
        "method": "keyword_fallback",
    }
