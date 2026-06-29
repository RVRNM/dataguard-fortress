"""Tests for the PII Scrubber engine."""

from __future__ import annotations

import pytest

from src.scrubber import Detection, PatternPreset, PIIScrubber, ScrubResult, _build_presets


class TestPIIScrubberBasics:
    """Basic tests for PIIScrubber initialization and properties."""

    def test_has_many_presets(self) -> None:
        """Verify we have 50+ presets as required."""
        scrubber = PIIScrubber(min_confidence=0.0)
        assert scrubber.preset_count >= 50, (
            f"Expected 50+ presets, got {scrubber.preset_count}"
        )

    def test_all_presets_loaded(self) -> None:
        """All presets from _build_presets are loaded when no filter."""
        presets = _build_presets()
        scrubber = PIIScrubber(min_confidence=0.0)
        assert scrubber.preset_count == len(presets)

    def test_preset_names_unique(self) -> None:
        """Each preset name should be unique."""
        presets = _build_presets()
        names = [p.name for p in presets]
        assert len(names) == len(set(names)), "Duplicate preset names found"

    def test_confidence_filtering(self) -> None:
        """High confidence filter should exclude low-confidence presets."""
        strict = PIIScrubber(min_confidence=0.90)
        loose = PIIScrubber(min_confidence=0.0)
        assert strict.preset_count < loose.preset_count

    def test_enabled_presets_filter(self) -> None:
        """Filtering by name should work."""
        scrubber = PIIScrubber(enabled_presets=["email", "ssn"])
        assert scrubber.preset_count == 2
        names = scrubber.get_preset_names()
        assert "email" in names
        assert "ssn" in names

    def test_get_preset_summary(self) -> None:
        """Preset summary should aggregate by entity type."""
        scrubber = PIIScrubber(min_confidence=0.0)
        summary = scrubber.get_preset_summary()
        assert "EMAIL" in summary
        assert "CREDIT_CARD" in summary  # multiple card presets
        assert summary["CREDIT_CARD"] >= 4  # Visa, MC, Amex, Discover


class TestPIIScrubbing:
    """Tests for PII detection and redaction."""

    @pytest.mark.asyncio
    async def test_scrub_email(self, scrubber: PIIScrubber) -> None:
        """Email addresses are detected and redacted."""
        text = "Contact me at alice@example.com please."
        result = await scrubber.scrub(text)
        assert "[REDACTED_EMAIL]" in result.scrubbed_text
        assert "alice@example.com" not in result.scrubbed_text
        assert result.scrubbed_count >= 1

    @pytest.mark.asyncio
    async def test_scrub_phone(self, scrubber: PIIScrubber) -> None:
        """Phone numbers are detected and redacted."""
        text = "Call me at 555-123-4567."
        result = await scrubber.scrub(text)
        assert "[REDACTED_PHONE]" in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_scrub_ssn(self, scrubber: PIIScrubber) -> None:
        """SSNs are detected and redacted."""
        text = "SSN: 123-45-6789 is what I have."
        result = await scrubber.scrub(text)
        assert "[REDACTED_SSN]" in result.scrubbed_text
        assert "123-45-6789" not in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_scrub_credit_card(self, scrubber: PIIScrubber) -> None:
        """Credit card numbers are detected and redacted."""
        text = "My card is 4111-1111-1111-1111."
        result = await scrubber.scrub(text)
        assert "REDACTED_CC" in result.scrubbed_text
        assert "4111-1111-1111-1111" not in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_scrub_openai_key(self, scrubber: PIIScrubber) -> None:
        """OpenAI API keys are detected and redacted."""
        text = "Here is my key: TEST_OPENAI_KEY_abcdefghijklmnopqrstuvwxyz1234567890"
        result = await scrubber.scrub(text)
        assert "[REDACTED_OPENAI_KEY]" in result.scrubbed_text
        assert "TEST_OPENAI_KEY_" not in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_scrub_aws_key(self, scrubber: PIIScrubber) -> None:
        """AWS access keys are detected and redacted."""
        text = "AWS key: FAKE_AWS_KEY is compromised."
        result = await scrubber.scrub(text)
        assert "[REDACTED_AWS_KEY]" in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_scrub_multiple(self, scrubber: PIIScrubber, sample_pii_text: str) -> None:
        """Multiple PII types in one text are all detected."""
        result = await scrubber.scrub(sample_pii_text)
        assert result.scrubbed_count >= 3  # email, SSN, phone at minimum
        assert "alice@example.com" not in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_scrub_clean_text(self, scrubber: PIIScrubber, sample_clean_text: str) -> None:
        """Text without PII passes through unchanged."""
        result = await scrubber.scrub(sample_clean_text)
        assert result.scrubbed_count == 0
        assert result.scrubbed_text == sample_clean_text

    @pytest.mark.asyncio
    async def test_scrub_empty_string(self, scrubber: PIIScrubber) -> None:
        """Empty string produces no detections."""
        result = await scrubber.scrub("")
        assert result.scrubbed_count == 0
        assert result.scrubbed_text == ""

    @pytest.mark.asyncio
    async def test_detection_metadata(self, scrubber: PIIScrubber) -> None:
        """Detections carry correct position and type info."""
        text = "Email: test@example.com here."
        result = await scrubber.scrub(text)
        assert len(result.detections) >= 1
        detection = result.detections[0]
        assert detection.entity_type == "EMAIL"
        assert detection.start >= 0
        assert detection.end > detection.start
        assert detection.confidence > 0.0
        assert "test@example.com" in detection.matched_text

    @pytest.mark.asyncio
    async def test_scrub_json(self, scrubber: PIIScrubber) -> None:
        """JSON structures are recursively scrubbed."""
        data = {"user": "alice@example.com", "age": 30}
        scrubbed, result = await scrubber.scrub_json(data)
        assert "[REDACTED_EMAIL]" in str(scrubbed)
        assert "alice@example.com" not in str(scrubbed)

    @pytest.mark.asyncio
    async def test_scrub_streaming(self, scrubber: PIIScrubber) -> None:
        """Streaming chunks are scrubbed independently."""
        chunk = "User bob@test.com sent a message."
        result = await scrubber.scrub_streaming(chunk)
        assert "[REDACTED_EMAIL]" in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_stripe_key_detection(self, scrubber: PIIScrubber) -> None:
        """Stripe keys are detected."""
        text = "Key: FAKE_STRIPE_KEY"
        result = await scrubber.scrub(text)
        assert "[REDACTED_STRIPE_KEY]" in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_jwt_detection(self, scrubber: PIIScrubber) -> None:
        """JWT tokens are detected."""
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
        text = f"Bearer {token}"
        result = await scrubber.scrub(text)
        # Either the JWT or the Bearer token pattern should match
        assert result.scrubbed_count >= 1
        assert token not in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_private_key_detection(self, scrubber: PIIScrubber) -> None:
        """PEM private keys are detected."""
        key_text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        result = await scrubber.scrub(key_text)
        assert "[REDACTED_PRIVATE_KEY]" in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_ethereum_address(self, scrubber: PIIScrubber) -> None:
        """Ethereum addresses are detected."""
        text = "Send ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"
        result = await scrubber.scrub(text)
        assert "[REDACTED_ETH_ADDRESS]" in result.scrubbed_text

    @pytest.mark.asyncio
    async def test_medical_record_number(self, scrubber: PIIScrubber) -> None:
        """Medical record numbers are detected."""
        text = "Patient MRN: 12345678 needs follow-up."
        result = await scrubber.scrub(text)
        assert "[REDACTED_MRN]" in result.scrubbed_text


class TestScrubResult:
    """Tests for the ScrubResult dataclass."""

    def test_default_values(self) -> None:
        result = ScrubResult(original_text="test", scrubbed_text="test")
        assert result.scrubbed_count == 0
        assert result.detections == []

    def test_add_detection(self) -> None:
        result = ScrubResult(original_text="test", scrubbed_text="test")
        detection = Detection(
            entity_type="EMAIL",
            start=0,
            end=4,
            confidence=0.95,
            matched_text="test",
        )
        result.add_detection(detection, "[REDACTED]")
        assert result.scrubbed_count == 1
        assert len(result.detections) == 1


class TestCustomPresets:
    """Tests for adding custom presets to the scrubber."""

    def test_custom_preset(self) -> None:
        """Custom PatternPreset can be added to the scrubber."""
        custom = PatternPreset(
            name="employee_id",
            pattern=__import__("re").compile(r"EMP-\d{6}"),
            entity_type="EMPLOYEE_ID",
            replacement="[REDACTED_EMP_ID]",
            confidence=0.99,
        )
        scrubber = PIIScrubber(enabled_presets=[], custom_presets=[custom])
        assert scrubber.preset_count == 1
        assert "employee_id" in scrubber.get_preset_names()
