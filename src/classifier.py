"""DataGuard Fortress — Data Classifier Module.

Classifies request body sensitivity levels using keyword heuristics
and PII density scoring.
"""

from __future__ import annotations

import asyncio
import enum
import re
from dataclasses import dataclass, field
from typing import ClassVar


# ---------------------------------------------------------------------------
# Enums & dataclasses
# ---------------------------------------------------------------------------

class SensitivityLevel(enum.IntEnum):
    """Ordered sensitivity levels (higher = more sensitive)."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


@dataclass
class ClassificationResult:
    """Result of classifying a piece of text."""

    level: SensitivityLevel
    score: float  # 0.0 – 1.0
    reasons: list[str] = field(default_factory=list)
    pii_density: float = 0.0

    # Convenience mapping for callers that want a string label
    @property
    def level_name(self) -> str:
        return self.level.name


# ---------------------------------------------------------------------------
# Keyword buckets
# ---------------------------------------------------------------------------

# Classified by sensitivity tier — each word contributes a weight tier.
_KEYWORDS_CONFIDENTIAL: ClassVar[dict[str, float]] = {
    "password": 0.9,
    "secret": 0.85,
    "passwd": 0.9,
    "authorization": 0.7,
    "token": 0.8,
    "api_key": 0.85,
    "api-key": 0.85,
    "apikey": 0.85,
    "access_key": 0.85,
    "private_key": 0.95,
    "session_id": 0.6,
    "credential": 0.85,
    "credentials": 0.85,
    "bearer": 0.6,
}

_KEYWORDS_INTERNAL: ClassVar[dict[str, float]] = {
    "internal": 0.4,
    "employee": 0.5,
    "payroll": 0.6,
    "monthly_report": 0.4,
    "quarterly": 0.3,
    "org_chart": 0.5,
    "memo": 0.3,
    "salary": 0.6,
    "compensation": 0.5,
}

_KEYWORDS_RESTRICTED: ClassVar[dict[str, float]] = {
    "classified": 0.95,
    "top_secret": 1.0,
    "restricted_data": 1.0,
    "health_record": 0.95,
    "medical": 0.8,
    "diagnosis": 0.85,
    "ssn": 1.0,
    "social_security": 1.0,
    "credit_card": 1.0,
    "cvv": 1.0,
    "pin": 0.9,
}


# ---------------------------------------------------------------------------
# PII regex patterns (used for density calculation)
# ---------------------------------------------------------------------------

_PII_PATTERNS: ClassVar[list[tuple[re.Pattern[str], str]]] = [
    # US SSN (with or without dashes)
    (re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"), "ssn"),
    # Email
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "email"),
    # Phone (US-style, various formats)
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "phone"),
    # Credit card (Visa/MC/AmEx inline, with/without dashes or spaces)
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "credit_card"),
    # IPv4 address
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "ip_address"),
    # Birth date (MM/DD/YYYY or YYYY-MM-DD)
    (re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b"), "date"),
]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class DataClassifier:
    """Classifies request-body text into PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED.

    Uses keyword heuristics and PII-density scoring.
    """

    def __init__(
        self,
        pii_density_threshold: float = 0.1,
    ) -> None:
        self.pii_density_threshold = pii_density_threshold

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def classify(self, text: str) -> ClassificationResult:
        """Classify *text* and return a :class:`ClassificationResult`.

        Wrapped in ``async`` so callers (async web frameworks) can use
        ``await`` without extra boilerplate.  The work itself is CPU-bound
        but lightweight, so we offload it to the default loop executor only
        when the string is very large.
        """
        # Offload only for large payloads; otherwise just run synchronously.
        if len(text) > 50_000:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self._classify_sync, text)
        return self._classify_sync(text)

    def classify_sync(self, text: str) -> ClassificationResult:
        """Synchronous convenience wrapper around :meth:`classify`."""
        return self._classify_sync(text)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _pii_density(self, text_lower: str) -> tuple[float, list[str]]:
        """Return PII-density in [0, 1] and the list of detected PII type names.

        Density is ``PII_hits / max(1, word_count)`` — the fraction of words
        that are part of a PII match.  We approximate by dividing the
        number of matches by the total word count.
        """
        words = text_lower.split()
        total = len(words)
        if total == 0:
            return 0.0, []

        detected: set[str] = set()
        match_count = 0
        for pattern, label in _PII_PATTERNS:
            hits = pattern.findall(text_lower)
            if hits:
                detected.add(label)
                match_count += len(hits)

        density = match_count / total
        return density, sorted(detected)

    def _keyword_score_and_reasons(
        self, text_lower: str
    ) -> tuple[float, SensitivityLevel, list[str]]:
        """Scan keyword buckets and return (max_score, worst_level, reasons)."""
        reasons: list[str] = []
        worst_level = SensitivityLevel.PUBLIC
        max_score = 0.0

        # RESTRICTED keywords
        for word, weight in _KEYWORDS_RESTRICTED.items():
            if word in text_lower:
                reasons.append(f"restricted_keyword('{word}', weight={weight})")
                if weight > max_score:
                    max_score = weight
                worst_level = SensitivityLevel.RESTRICTED

        # CONFIDENTIAL keywords
        for word, weight in _KEYWORDS_CONFIDENTIAL.items():
            if word in text_lower:
                reasons.append(f"confidential_keyword('{word}', weight={weight})")
                if weight > max_score:
                    max_score = weight
                if worst_level < SensitivityLevel.CONFIDENTIAL:
                    worst_level = SensitivityLevel.CONFIDENTIAL

        # INTERNAL keywords
        for word, weight in _KEYWORDS_INTERNAL.items():
            if word in text_lower:
                reasons.append(f"internal_keyword('{word}', weight={weight})")
                if weight > max_score:
                    max_score = weight
                if worst_level < SensitivityLevel.INTERNAL:
                    worst_level = SensitivityLevel.INTERNAL

        return max_score, worst_level, reasons

    def _classify_sync(self, text: str) -> ClassificationResult:
        if not text:
            return ClassificationResult(
                level=SensitivityLevel.PUBLIC,
                score=0.0,
                reasons=["empty_text"],
                pii_density=0.0,
            )

        text_lower = text.lower()

        # 1. PII density
        pii_density, pii_types = self._pii_density(text_lower)

        # 2. Keyword heuristics
        kw_score, kw_level, kw_reasons = self._keyword_score_and_reasons(text_lower)
        reasons = list(kw_reasons)

        # 3. Apply rules
        final_level = kw_level

        # Rule: high PII density → clamp to RESTRICTED
        if pii_density > self.pii_density_threshold:
            final_level = SensitivityLevel.RESTRICTED
            reasons.append(
                f"pii_density({pii_density:.4f}) > threshold({self.pii_density_threshold})"
            )
            reasons.extend(f"pii_detected({t})" for t in pii_types)

        # 4. Compute composite score (0-1)
        #    Mix keyword score with PII density; take max to avoid under-scoring.
        score = min(1.0, max(kw_score, pii_density))

        # If nothing flagged, it's PUBLIC
        if not reasons:
            reasons.append("no_sensitive_indicators")

        return ClassificationResult(
            level=final_level,
            score=score,
            reasons=reasons,
            pii_density=pii_density,
        )
