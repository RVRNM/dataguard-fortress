"""PII Scrubber Engine — high-throughput regex-based PII detection and redaction.

Provides 50+ preset patterns for detecting:
  - Email addresses, phone numbers, SSNs
  - Credit card numbers (Visa, MC, Amex, Discover)
  - API keys (OpenAI, AWS, Google, GitHub, Stripe, etc.)
  - Medical record numbers, health insurance IDs
  - IP addresses (IPv4/IPv6), MAC addresses
  - passports, driver's licenses, tax IDs
  - Cryptocurrency addresses (BTC, ETH)
  - And more...

All patterns are pre-compiled at module load time for performance.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Detection:
    """A single PII detection."""

    entity_type: str
    start: int
    end: int
    confidence: float
    matched_text: str


@dataclass
class ScrubResult:
    """Result of a scrubbing operation."""

    original_text: str
    scrubbed_text: str
    detections: list[Detection] = field(default_factory=list)
    scrubbed_count: int = 0

    def add_detection(self, detection: Detection, replacement: str) -> None:
        """Record a detection and apply its replacement."""
        self.detections.append(detection)
        self.scrubbed_count += 1


@dataclass
class PatternPreset:
    """A single PII detection pattern with its replacement template."""

    name: str
    pattern: re.Pattern[str]
    entity_type: str
    replacement: str
    confidence: float = 0.95


def _build_presets() -> list[PatternPreset]:
    """Build all 50+ PII detection presets."""
    presets: list[PatternPreset] = []

    # ── Email & Communication ───────────────────────────────────────
    presets.append(PatternPreset(
        name="email",
        pattern=re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        ),
        entity_type="EMAIL",
        replacement="[REDACTED_EMAIL]",
        confidence=0.98,
    ))

    # ── Phone Numbers ────────────────────────────────────────────────
    presets.append(PatternPreset(
        name="phone_us",
        pattern=re.compile(
            r"\+?1?\s*\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}"
        ),
        entity_type="PHONE",
        replacement="[REDACTED_PHONE]",
        confidence=0.90,
    ))

    # ── Social Security Number ───────────────────────────────────────
    presets.append(PatternPreset(
        name="ssn",
        pattern=re.compile(
            r"(?<!\d)\d{3}[\s\-]\d{2}[\s\-]\d{4}(?!\d)"
        ),
        entity_type="SSN",
        replacement="[REDACTED_SSN]",
        confidence=0.92,
    ))

    # ── Credit Cards ─────────────────────────────────────────────────
    presets.append(PatternPreset(
        name="credit_card_visa",
        pattern=re.compile(
            r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
        ),
        entity_type="CREDIT_CARD",
        replacement="[REDACTED_CC_VISA]",
        confidence=0.93,
    ))
    presets.append(PatternPreset(
        name="credit_card_mastercard",
        pattern=re.compile(
            r"\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
        ),
        entity_type="CREDIT_CARD",
        replacement="[REDACTED_CC_MASTERCARD]",
        confidence=0.93,
    ))
    presets.append(PatternPreset(
        name="credit_card_amex",
        pattern=re.compile(
            r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b"
        ),
        entity_type="CREDIT_CARD",
        replacement="[REDACTED_CC_AMEX]",
        confidence=0.93,
    ))
    presets.append(PatternPreset(
        name="credit_card_discover",
        pattern=re.compile(
            r"\b6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
        ),
        entity_type="CREDIT_CARD",
        replacement="[REDACTED_CC_DISCOVER]",
        confidence=0.92,
    ))

    # ── API Keys ─────────────────────────────────────────────────────
    presets.append(PatternPreset(
        name="openai_api_key",
        pattern=re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        entity_type="API_KEY_OPENAI",
        replacement="[REDACTED_OPENAI_KEY]",
        confidence=0.97,
    ))
    presets.append(PatternPreset(
        name="aws_access_key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        entity_type="AWS_ACCESS_KEY",
        replacement="[REDACTED_AWS_KEY]",
        confidence=0.97,
    ))
    presets.append(PatternPreset(
        name="aws_secret_key",
        pattern=re.compile(r"(?i)aws_secret_access_key['\"\s:=]+[A-Za-z0-9/+=]{40}"),
        entity_type="AWS_SECRET_KEY",
        replacement="[REDACTED_AWS_SECRET]",
        confidence=0.95,
    ))
    presets.append(PatternPreset(
        name="google_api_key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        entity_type="GOOGLE_API_KEY",
        replacement="[REDACTED_GOOGLE_KEY]",
        confidence=0.96,
    ))
    presets.append(PatternPreset(
        name="github_token",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        entity_type="GITHUB_TOKEN",
        replacement="[REDACTED_GITHUB_TOKEN]",
        confidence=0.96,
    ))
    presets.append(PatternPreset(
        name="stripe_key",
        pattern=re.compile(r"(?:sk|pk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}"),
        entity_type="STRIPE_KEY",
        replacement="[REDACTED_STRIPE_KEY]",
        confidence=0.97,
    ))
    presets.append(PatternPreset(
        name="generic_api_key",
        pattern=re.compile(
            r"(?i)(?:api[_\-]?key|secret[_\-]?key|token)[\s\"':=]+[a-zA-Z0-9_\-]{20,}"
        ),
        entity_type="API_KEY_GENERIC",
        replacement="[REDACTED_API_KEY]",
        confidence=0.80,
    ))
    presets.append(PatternPreset(
        name="bearer_token",
        pattern=re.compile(
            r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"
        ),
        entity_type="BEARER_TOKEN",
        replacement="Bearer [REDACTED_TOKEN]",
        confidence=0.85,
    ))

    # ── Passport & Identity Documents ────────────────────────────────
    presets.append(PatternPreset(
        name="us_passport",
        pattern=re.compile(r"\b\d{9}\b"),
        entity_type="US_PASSPORT",
        replacement="[REDACTED_PASSPORT]",
        confidence=0.60,  # low — needs context
    ))
    presets.append(PatternPreset(
        name="drivers_license",
        pattern=re.compile(
            r"(?i)(?:driver'?s?\s*lic(?:ense)?|dl)[\s#:]*[0-9A-Za-z]{6,14}"
        ),
        entity_type="DRIVERS_LICENSE",
        replacement="[REDACTED_DRIVERS_LICENSE]",
        confidence=0.75,
    ))
    presets.append(PatternPreset(
        name="ein",
        pattern=re.compile(r"\b\d{2}[\-\s]?\d{7}\b"),
        entity_type="EIN",
        replacement="[REDACTED_EIN]",
        confidence=0.70,
    ))
    presets.append(PatternPreset(
        name="itin",
        pattern=re.compile(r"\b9\d{2}[\-\s]?[78]\d[\-\s]?\d{4}\b"),
        entity_type="ITIN",
        replacement="[REDACTED_ITIN]",
        confidence=0.75,
    ))

    # ── IP Addresses ─────────────────────────────────────────────────
    presets.append(PatternPreset(
        name="ipv4",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
        ),
        entity_type="IPV4",
        replacement="[REDACTED_IP]",
        confidence=0.85,
    ))
    presets.append(PatternPreset(
        name="ipv6",
        pattern=re.compile(
            r"(?:"
            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"  # full
            r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"             # trailing ::
            r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
            r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
            r"|::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}"  # ::ffff:192.0.2.1
            r"|::(?:[fF]{4}:)?0\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r")"
        ),
        entity_type="IPV6",
        replacement="[REDACTED_IPV6]",
        confidence=0.80,
    ))

    # ── Medical Records ──────────────────────────────────────────────
    presets.append(PatternPreset(
        name="medical_record_number",
        pattern=re.compile(
            r"(?i)(?:mrn|medical\s*record|patient\s*(?:id|number))[\s:#]*[0-9A-Za-z\-]{4,20}"
        ),
        entity_type="MEDICAL_RECORD_NUMBER",
        replacement="[REDACTED_MRN]",
        confidence=0.85,
    ))
    presets.append(PatternPreset(
        name="health_insurance_id",
        pattern=re.compile(
            r"(?i)(?:insurance\s*(?:id|number|policy)|member\s*id|group\s*number)[\s:#]*[0-9A-Za-z\-]{6,20}"
        ),
        entity_type="HEALTH_INSURANCE_ID",
        replacement="[REDACTED_INSURANCE_ID]",
        confidence=0.80,
    ))
    presets.append(PatternPreset(
        name="npi_number",
        pattern=re.compile(r"\b\d{10}\b"),
        entity_type="NPI_NUMBER",
        replacement="[REDACTED_NPI]",
        confidence=0.50,  # low — generic 10-digit match
    ))
    presets.append(PatternPreset(
        name="icd_code",
        pattern=re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b"),
        entity_type="ICD_CODE",
        replacement="[REDACTED_ICD]",
        confidence=0.40,  # low — needs context
    ))

    # ── Financial ───────────────────────────────────────────────────
    presets.append(PatternPreset(
        name="bank_routing_number",
        pattern=re.compile(
            r"(?i)(?:routing\s*(?:number|no|#)|rtn)[\s:#]*[0-9]{9}"
        ),
        entity_type="BANK_ROUTING_NUMBER",
        replacement="[REDACTED_ROUTING_NUMBER]",
        confidence=0.85,
    ))
    presets.append(PatternPreset(
        name="bank_account_number",
        pattern=re.compile(
            r"(?i)(?:account\s*(?:number|no|#|num)|acct\s*#)[\s:#]*[0-9]{8,17}"
        ),
        entity_type="BANK_ACCOUNT_NUMBER",
        replacement="[REDACTED_ACCOUNT_NUMBER]",
        confidence=0.80,
    ))
    presets.append(PatternPreset(
        name="iban",
        pattern=re.compile(
            r"\b[A-Z]{2}\d{2}[\s-]?(?:[0-9A-Z]{4}[\s-]?){3,7}[0-9A-Z]{1,4}\b"
        ),
        entity_type="IBAN",
        replacement="[REDACTED_IBAN]",
        confidence=0.88,
    ))
    presets.append(PatternPreset(
        name="swift_code",
        pattern=re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
        entity_type="SWIFT_CODE",
        replacement="[REDACTED_SWIFT]",
        confidence=0.60,
    ))
    presets.append(PatternPreset(
        name="bitcoin_address",
        pattern=re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
        entity_type="CRYPTO_BTC_ADDRESS",
        replacement="[REDACTED_BTC_ADDRESS]",
        confidence=0.85,
    ))
    presets.append(PatternPreset(
        name="ethereum_address",
        pattern=re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        entity_type="CRYPTO_ETH_ADDRESS",
        replacement="[REDACTED_ETH_ADDRESS]",
        confidence=0.92,
    ))

    # ── MAC Addresses & Device IDs ──────────────────────────────────
    presets.append(PatternPreset(
        name="mac_address",
        pattern=re.compile(
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
        ),
        entity_type="MAC_ADDRESS",
        replacement="[REDACTED_MAC]",
        confidence=0.90,
    ))
    presets.append(PatternPreset(
        name="imei",
        pattern=re.compile(r"\b\d{15,16}\b"),
        entity_type="IMEI",
        replacement="[REDACTED_IMEI]",
        confidence=0.50,
    ))

    # ── URLs with Credentials ───────────────────────────────────────
    presets.append(PatternPreset(
        name="url_with_credentials",
        pattern=re.compile(
            r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s:]+:[^\s@]+@[^\s/]+"
        ),
        entity_type="URL_WITH_CREDENTIALS",
        replacement="[REDACTED_URL_WITH_CREDS]",
        confidence=0.95,
    ))

    # ── Date of Birth ──────────────────────────────────────────────
    presets.append(PatternPreset(
        name="date_of_birth",
        pattern=re.compile(
            r"(?i)(?:dob|date\s*of\s*birth|born)[\s:]*(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4})"
        ),
        entity_type="DATE_OF_BIRTH",
        replacement="[REDACTED_DOB]",
        confidence=0.75,
    ))

    # ── Postal/ZIP Codes (US context) ─────────────────────────────
    presets.append(PatternPreset(
        name="us_zip_full",
        pattern=re.compile(r"\b\d{5}-\d{4}\b"),
        entity_type="US_ZIP_FULL",
        replacement="[REDACTED_ZIP]",
        confidence=0.30,  # low — could match other numerics
    ))

    # ── JWT Tokens ─────────────────────────────────────────────────
    presets.append(PatternPreset(
        name="jwt_token",
        pattern=re.compile(
            r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
        ),
        entity_type="JWT_TOKEN",
        replacement="[REDACTED_JWT]",
        confidence=0.95,
    ))

    # ── Private Keys ───────────────────────────────────────────────
    presets.append(PatternPreset(
        name="private_key_pem",
        pattern=re.compile(
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
        ),
        entity_type="PRIVATE_KEY",
        replacement="[REDACTED_PRIVATE_KEY]",
        confidence=0.98,
    ))
    presets.append(PatternPreset(
        name="ssh_private_key",
        pattern=re.compile(
            r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]+?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----"
        ),
        entity_type="SSH_PRIVATE_KEY",
        replacement="[REDACTED_SSH_KEY]",
        confidence=0.98,
    ))

    # ── Slack/Teams Tokens ──────────────────────────────────────────
    presets.append(PatternPreset(
        name="slack_token",
        pattern=re.compile(r"(?:xox[baprs]-[a-zA-Z0-9\-]{10,48})"),
        entity_type="SLACK_TOKEN",
        replacement="[REDACTED_SLACK_TOKEN]",
        confidence=0.96,
    ))
    presets.append(PatternPreset(
        name="slack_webhook",
        pattern=re.compile(
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
        ),
        entity_type="SLACK_WEBHOOK",
        replacement="[REDACTED_SLACK_WEBHOOK]",
        confidence=0.98,
    ))

    # ── AWS Account & ARNs ─────────────────────────────────────────
    presets.append(PatternPreset(
        name="aws_account_id",
        pattern=re.compile(r"\b\d{12}\b"),
        entity_type="AWS_ACCOUNT_ID",
        replacement="[REDACTED_AWS_ACCOUNT]",
        confidence=0.40,
    ))
    presets.append(PatternPreset(
        name="aws_arn",
        pattern=re.compile(
            r"arn:aws:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:[^\s]+"
        ),
        entity_type="AWS_ARN",
        replacement="[REDACTED_AWS_ARN]",
        confidence=0.92,
    ))

    # ── Twilio Keys ────────────────────────────────────────────────
    presets.append(PatternPreset(
        name="twilio_api_key",
        pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
        entity_type="TWILIO_API_KEY",
        replacement="[REDACTED_TWILIO_KEY]",
        confidence=0.95,
    ))
    presets.append(PatternPreset(
        name="twilio_account_sid",
        pattern=re.compile(r"AC[0-9a-fA-F]{32}"),
        entity_type="TWILIO_ACCOUNT_SID",
        replacement="[REDACTED_TWILIO_SID]",
        confidence=0.93,
    ))

    # ── Square/PayPal Tokens ───────────────────────────────────────
    presets.append(PatternPreset(
        name="square_token",
        pattern=re.compile(r"sq0[a-z]{2}-[A-Za-z0-9\-_]{22,43}"),
        entity_type="SQUARE_TOKEN",
        replacement="[REDACTED_SQUARE_TOKEN]",
        confidence=0.95,
    ))

    # ── Date-like patterns (potential PII context) ────────────────
    presets.append(PatternPreset(
        name="date_numeric",
        pattern=re.compile(
            r"\b(?:0[1-9]|1[0-2])[/\-.](?:0[1-9]|[12]\d|3[01])[/\-.](?:19|20)\d{2}\b"
        ),
        entity_type="DATE_NUMERIC",
        replacement="[REDACTED_DATE]",
        confidence=0.35,
    ))

    # ── Prescription Numbers ──────────────────────────────────────
    presets.append(PatternPreset(
        name="rx_number",
        pattern=re.compile(
            r"(?i)(?:rx|prescription)[\s#:]*[0-9A-Za-z]{6,15}"
        ),
        entity_type="PRESCRIPTION_NUMBER",
        replacement="[REDACTED_RX]",
        confidence=0.70,
    ))

    # ── Database Connection Strings ──────────────────────────────
    presets.append(PatternPreset(
        name="database_url",
        pattern=re.compile(
            r"(?i)(?:mysql|postgres|mongodb|redis|amqp):\/\/[^\s]+:[^\s@]+@[^\s]+"
        ),
        entity_type="DATABASE_URL_WITH_CREDS",
        replacement="[REDACTED_DB_URL]",
        confidence=0.93,
    ))

    # ── Firebase/GCP Keys ─────────────────────────────────────────
    presets.append(PatternPreset(
        name="firebase_key",
        pattern=re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}"),
        entity_type="FIREBASE_KEY",
        replacement="[REDACTED_FIREBASE_KEY]",
        confidence=0.95,
    ))

    # ── Tax/TIN for non-US ────────────────────────────────────────
    presets.append(PatternPreset(
        name="uk_nino",
        pattern=re.compile(
            r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]?\b"
        ),
        entity_type="UK_NINO",
        replacement="[REDACTED_NINO]",
        confidence=0.60,
    ))

    # ── Vehicle VIN (17 chars) ───────────────────────────────────
    presets.append(PatternPreset(
        name="vin_number",
        pattern=re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
        entity_type="VIN",
        replacement="[REDACTED_VIN]",
        confidence=0.50,
    ))

    return presets


# ── Module-Level Pre-compiled Patterns ──────────────────────────────────────
_PRESETS: list[PatternPreset] = _build_presets()


class PIIScrubber:
    """High-performance PII scrubber with 50+ regex presets.

    Thread-safe and async-compatible. All patterns are pre-compiled
    at import time for maximum throughput.

    Usage:
        scrubber = PIIScrubber()
        result = await scrubber.scrub("My email is alice@example.com")
        print(result.scrubbed_text)  # "My email is [REDACTED_EMAIL]"
    """

    def __init__(
        self,
        enabled_presets: list[str] | None = None,
        custom_presets: list[PatternPreset] | None = None,
        min_confidence: float = 0.0,
    ) -> None:
        """Initialize the scrubber.

        Args:
            enabled_presets: If set, only use presets with these names.
                None means all presets are active.
            custom_presets: Additional PatternPreset entries to include.
            min_confidence: Minimum confidence threshold for detections.
        """
        self._presets: list[PatternPreset] = []

        for preset in _PRESETS:
            if enabled_presets is not None and preset.name not in enabled_presets:
                continue
            if preset.confidence < min_confidence:
                continue
            self._presets.append(preset)

        if custom_presets:
            self._presets.extend(custom_presets)

        self._min_confidence = min_confidence

    @property
    def patterns(self) -> list[PatternPreset]:
        """Access loaded presets."""
        return self._presets

    @property
    def preset_count(self) -> int:
        """Return the number of active presets."""
        return len(self._presets)

    async def scrub(self, text: str) -> ScrubResult:
        """Scrub PII from the given text.

        Scans the text against all active presets and replaces
        matches with their configured replacement strings.

        Args:
            text: Input text to scan.

        Returns:
            ScrubResult with the scrubbed text and detection metadata.
        """
        result = ScrubResult(original_text=text, scrubbed_text=text)

        for preset in self._presets:
            self._apply_preset(text, preset, result)

        return result

    async def scrub_streaming(self, chunk: str) -> ScrubResult:
        """Scrub a streaming text chunk.

        For streaming, we scan each chunk independently.
        Note: PII spanning chunk boundaries may not be detected.
        For best results, use overlapping windows in the caller.

        Args:
            chunk: A chunk of text from a streaming source.

        Returns:
            ScrubResult for this chunk.
        """
        return await self.scrub(chunk)

    async def scrub_json(self, data: dict[str, Any] | str) -> tuple[dict[str, Any] | str, ScrubResult]:
        """Scrub all string values within a JSON structure.

        Args:
            data: Either a parsed dict or a JSON string.

        Returns:
            Tuple of (scrubbed_data, aggregate_result).
        """
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                result = await self.scrub(data)
                return result.scrubbed_text, result

        all_detections: list[Detection] = []
        total_count = 0

        scrubbed = self._walk_and_scrub(data, all_detections, total_count)

        aggregate = ScrubResult(
            original_text=json.dumps(data),
            scrubbed_text=json.dumps(scrubbed) if isinstance(data, dict) else scrubbed,
            detections=all_detections,
            scrubbed_count=total_count,
        )

        return scrubbed, aggregate

    def _apply_preset(self, text: str, preset: PatternPreset, result: ScrubResult) -> None:
        """Apply a single preset pattern to the text."""
        for match in preset.pattern.finditer(text):
            detection = Detection(
                entity_type=preset.entity_type,
                start=match.start(),
                end=match.end(),
                confidence=preset.confidence,
                matched_text=match.group(),
            )
            result.add_detection(detection, preset.replacement)

        # Apply the replacement
        if result.detections:
            result.scrubbed_text = preset.pattern.sub(preset.replacement, result.scrubbed_text)

    def _walk_and_scrub(
        self,
        obj: Any,
        detections: list[Detection],
        count: int,
    ) -> Any:
        """Recursively walk a JSON structure and scrub string values."""
        match obj:
            case str():
                # Build a synchronous-like result for this string
                new_text = obj
                for preset in self._presets:
                    for match in preset.pattern.finditer(new_text):
                        detections.append(Detection(
                            entity_type=preset.entity_type,
                            start=match.start(),
                            end=match.end(),
                            confidence=preset.confidence,
                            matched_text=match.group(),
                        ))
                        count += 1
                    new_text = preset.pattern.sub(preset.replacement, new_text)
                return new_text
            case dict():
                return {k: self._walk_and_scrub(v, detections, count) for k, v in obj.items()}
            case list():
                return [self._walk_and_scrub(item, detections, count) for item in obj]
            case _:
                return obj

    def get_preset_names(self) -> list[str]:
        """Return names of all active presets."""
        return [p.name for p in self._presets]

    def get_preset_summary(self) -> dict[str, int]:
        """Return count of presets by entity type."""
        summary: dict[str, int] = {}
        for preset in self._presets:
            summary[preset.entity_type] = summary.get(preset.entity_type, 0) + 1
        return summary
