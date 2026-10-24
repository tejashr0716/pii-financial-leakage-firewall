import re
import time
from typing import List, Tuple
from src.models import LeakageFinding
from src.validators import (
    validate_luhn,
    identify_card_brand,
    validate_iban,
    validate_ssn,
    mask_value
)

# Compiled detection patterns
CARD_PATTERN = re.compile(r"\b(?:\d[ \-]*?){13,19}\b")
IBAN_PATTERN = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ \-]?[A-Z0-9]){11,30}\b")
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
STRIPE_PATTERN = re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b")
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)


class DLPDetector:
    """High-performance inspection and redaction engine for financial PII and credentials."""

    def scan_text(self, text: str, mask_mode: str = "PARTIAL_MASK") -> List[LeakageFinding]:
        if not text:
            return []

        findings: List[LeakageFinding] = []
        occupied_spans = []

        def is_overlapping(start: int, end: int) -> bool:
            for s, e in occupied_spans:
                if max(start, s) < min(end, e):
                    return True
            return False

        # 1. Private Keys
        for m in PRIVATE_KEY_PATTERN.finditer(text):
            start, end = m.span()
            raw = m.group()
            occupied_spans.append((start, end))
            findings.append(LeakageFinding(
                finding_type="PRIVATE_KEY",
                severity="CRITICAL",
                raw_match=raw,
                masked_value=mask_value(raw, "PRIVATE_KEY", mask_mode),
                start_index=start,
                end_index=end,
                validation_rule="PEM_HEADER_FOOTER_BLOCK",
                confidence=1.0
            ))

        # 2. Stripe API Keys
        for m in STRIPE_PATTERN.finditer(text):
            start, end = m.span()
            if is_overlapping(start, end):
                continue
            raw = m.group()
            occupied_spans.append((start, end))
            severity = "CRITICAL" if "_live_" in raw else "HIGH"
            findings.append(LeakageFinding(
                finding_type="API_KEY_STRIPE",
                severity=severity,
                raw_match=raw,
                masked_value=mask_value(raw, "API_KEY_STRIPE", mask_mode),
                start_index=start,
                end_index=end,
                validation_rule="STRIPE_KEY_ENTROPY_PREFIX",
                confidence=1.0
            ))

        # 3. AWS Access Keys
        for m in AWS_KEY_PATTERN.finditer(text):
            start, end = m.span()
            if is_overlapping(start, end):
                continue
            raw = m.group()
            occupied_spans.append((start, end))
            findings.append(LeakageFinding(
                finding_type="API_KEY_AWS",
                severity="CRITICAL",
                raw_match=raw,
                masked_value=mask_value(raw, "API_KEY_AWS", mask_mode),
                start_index=start,
                end_index=end,
                validation_rule="AWS_AKIA_IDENTIFIER",
                confidence=1.0
            ))

        # 4. Social Security Numbers (SSN)
        for m in SSN_PATTERN.finditer(text):
            start, end = m.span()
            if is_overlapping(start, end):
                continue
            raw = m.group()
            if validate_ssn(raw):
                occupied_spans.append((start, end))
                findings.append(LeakageFinding(
                    finding_type="SSN",
                    severity="CRITICAL",
                    raw_match=raw,
                    masked_value=mask_value(raw, "SSN", mask_mode),
                    start_index=start,
                    end_index=end,
                    validation_rule="US_SSA_AREA_GROUP_RULES",
                    confidence=1.0
                ))

        # 5. IBAN
        for m in IBAN_PATTERN.finditer(text):
            start, end = m.span()
            if is_overlapping(start, end):
                continue
            raw = m.group()
            if validate_iban(raw):
                occupied_spans.append((start, end))
                findings.append(LeakageFinding(
                    finding_type="IBAN",
                    severity="CRITICAL",
                    raw_match=raw,
                    masked_value=mask_value(raw, "IBAN", mask_mode),
                    start_index=start,
                    end_index=end,
                    validation_rule="MOD97_ISO7064_CHECKSUM",
                    confidence=1.0
                ))

        # 6. Credit Card PANs (via Luhn validation)
        for m in CARD_PATTERN.finditer(text):
            start, end = m.span()
            if is_overlapping(start, end):
                continue
            raw = m.group()
            digits = re.sub(r"\D", "", raw)
            if 13 <= len(digits) <= 19 and validate_luhn(digits):
                brand = identify_card_brand(digits)
                occupied_spans.append((start, end))
                findings.append(LeakageFinding(
                    finding_type="CREDIT_CARD",
                    severity="CRITICAL",
                    raw_match=raw,
                    masked_value=mask_value(raw, "CREDIT_CARD", mask_mode),
                    start_index=start,
                    end_index=end,
                    validation_rule=f"LUHN_MOD10_{brand}",
                    confidence=1.0
                ))

        # Sort findings by start index
        findings.sort(key=lambda f: f.start_index)
        return findings

    def redact_text(self, text: str, mode: str = "PARTIAL_MASK") -> Tuple[str, List[LeakageFinding]]:
        """Redact detected sensitive entities in reverse order to preserve string slicing."""
        findings = self.scan_text(text, mask_mode=mode)
        if not findings:
            return text, []

        redacted = text
        # Replace from end to start so indices remain valid
        for f in reversed(findings):
            replacement = f.masked_value
            redacted = redacted[:f.start_index] + replacement + redacted[f.end_index:]

        return redacted, findings


dlp_detector = DLPDetector()
