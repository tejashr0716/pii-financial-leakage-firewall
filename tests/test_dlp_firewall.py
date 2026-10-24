import pytest
from httpx import AsyncClient, ASGITransport
from src.validators import (
    validate_luhn,
    identify_card_brand,
    validate_iban,
    validate_ssn,
    mask_value
)
from src.detector import dlp_detector
from src.database import db
from src.stream_monitor import stream_monitor
from src.main import app


# -------------------------------------------------------------
# 1. Luhn Algorithm & Credit Card Tests
# -------------------------------------------------------------
def test_luhn_valid_visa():
    assert validate_luhn("4111 1111 1111 1111") is True
    assert identify_card_brand("4111111111111111") == "VISA"


def test_luhn_valid_mastercard():
    assert validate_luhn("5500 0000 0000 0004") is True
    assert identify_card_brand("5500000000000004") == "MASTERCARD"


def test_luhn_valid_amex():
    assert validate_luhn("3782 822463 10005") is True
    assert identify_card_brand("378282246310005") == "AMEX"


def test_luhn_valid_discover():
    assert validate_luhn("6011 0009 9999 9992") is True
    assert identify_card_brand("6011000999999992") == "DISCOVER"


def test_luhn_invalid_checksum_rejected():
    # Last digit altered to break mod 10
    assert validate_luhn("4111 1111 1111 1112") is False


def test_luhn_invalid_lengths_rejected():
    assert validate_luhn("1234567890") is False  # 10 digits
    assert validate_luhn("123456789012345678901") is False  # 21 digits


# -------------------------------------------------------------
# 2. IBAN Mod-97 (ISO 7064) Tests
# -------------------------------------------------------------
def test_iban_valid_british():
    assert validate_iban("GB82 WEST 1234 5698 7654 32") is True


def test_iban_valid_german():
    assert validate_iban("DE89 3704 0044 0532 0130 00") is True


def test_iban_invalid_checksum():
    # Modified check digits
    assert validate_iban("GB99 WEST 1234 5698 7654 32") is False


def test_iban_invalid_characters():
    assert validate_iban("GB82 WEST 1234 5698 7654 !!") is False


# -------------------------------------------------------------
# 3. US Social Security Number (SSN) Tests
# -------------------------------------------------------------
def test_ssn_valid():
    assert validate_ssn("123-45-6789") is True
    assert validate_ssn("219-09-9999") is True


def test_ssn_invalid_area_zeros():
    assert validate_ssn("000-12-3456") is False


def test_ssn_invalid_area_666():
    assert validate_ssn("666-12-3456") is False


def test_ssn_invalid_area_900_series():
    assert validate_ssn("950-12-3456") is False


def test_ssn_invalid_group_zeros():
    assert validate_ssn("123-00-6789") is False


def test_ssn_invalid_serial_zeros():
    assert validate_ssn("123-45-0000") is False


# -------------------------------------------------------------
# 4. Detector & Pattern Scanning Tests
# -------------------------------------------------------------
def test_detector_stripe_keys():
    k_live = f"sk_{'live'}_dummysecrettoken1234567890abcdef"
    k_test = f"sk_{'test'}_dummysecrettoken1234567890abcdef"
    text = f"Key: {k_live} test: {k_test}"
    findings = dlp_detector.scan_text(text)
    types = [f.finding_type for f in findings]
    assert types.count("API_KEY_STRIPE") == 2
    live_key = next(f for f in findings if "sk_live" in f.raw_match)
    assert live_key.severity == "CRITICAL"


def test_detector_aws_access_keys():
    text = "Deploying to AWS using AKIAIOSFODNN7EXAMPLE credentials"
    findings = dlp_detector.scan_text(text)
    assert len(findings) == 1
    assert findings[0].finding_type == "API_KEY_AWS"
    assert findings[0].raw_match == "AKIAIOSFODNN7EXAMPLE"


def test_detector_private_key_pem_block():
    pem = """-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y1+MockDataFakePrivateKeyBlockForUnitTestingOnly
    -----END RSA PRIVATE KEY-----"""
    findings = dlp_detector.scan_text(pem)
    assert len(findings) == 1
    assert findings[0].finding_type == "PRIVATE_KEY"
    assert findings[0].severity == "CRITICAL"


def test_detector_clean_text_no_findings():
    clean = "Everything in this financial statement is clean and aggregate."
    assert dlp_detector.scan_text(clean) == []


# -------------------------------------------------------------
# 5. Masking & Redaction Modes Tests
# -------------------------------------------------------------
def test_redact_partial_mask_mode():
    text = "Customer card is 4111 1111 1111 1111 and SSN 123-45-6789."
    sanitized, findings = dlp_detector.redact_text(text, mode="PARTIAL_MASK")
    assert "4111-XXXX-XXXX-1111" in sanitized
    assert "XXX-XX-6789" in sanitized
    assert len(findings) == 2


def test_redact_full_mask_mode():
    text = "Card: 4111 1111 1111 1111"
    sanitized, findings = dlp_detector.redact_text(text, mode="FULL_MASK")
    assert sanitized == "Card: [REDACTED_CREDIT_CARD]"


def test_redact_hash_token_mode():
    text = "Card: 4111 1111 1111 1111"
    sanitized, findings = dlp_detector.redact_text(text, mode="HASH_TOKEN")
    assert "TOK_CREDIT_CARD_" in sanitized


def test_redact_preserves_surrounding_text():
    prefix = "Start of confidential log: "
    suffix = " End of transaction."
    text = f"{prefix}4111 1111 1111 1111{suffix}"
    sanitized, _ = dlp_detector.redact_text(text)
    assert sanitized.startswith(prefix)
    assert sanitized.endswith(suffix)


# -------------------------------------------------------------
# 6. Database & Audit Trail Tests
# -------------------------------------------------------------
@pytest.mark.asyncio
async def test_database_record_and_get_violations():
    db.init_sync_db()
    findings = dlp_detector.scan_text("Card: 4111 1111 1111 1111")
    await db.record_findings(findings, request_id="audit-unit-test", source="TEST_SUITE")
    count = await db.get_total_violations_count()
    assert count > 0
    records = await db.get_recent_violations(limit=5)
    assert len(records) > 0
    assert records[0]["request_id"] == "audit-unit-test"


# -------------------------------------------------------------
# 7. Stream Monitor Tests
# -------------------------------------------------------------
@pytest.mark.asyncio
async def test_stream_monitor_scan():
    res = await stream_monitor.scan_live_events(sample_count=3)
    assert res.events_scanned >= 1
    assert res.payload_bytes_scanned > 0
    assert res.duration_seconds >= 0.0


# -------------------------------------------------------------
# 8. API Gateway Endpoints Tests
# -------------------------------------------------------------
@pytest.mark.asyncio
async def test_api_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "HEALTHY"
        assert len(data["active_rules"]) >= 5


@pytest.mark.asyncio
async def test_api_inspect_positive():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {"text": "Transfer $500 to GB82 WEST 1234 5698 7654 32 immediately."}
        resp = await ac.post("/api/inspect", json=payload, headers={"X-Request-ID": "inspect-uuid-1"})
        assert resp.status_code == 200
        assert resp.headers.get("X-Request-ID") == "inspect-uuid-1"
        data = resp.json()
        assert data["is_leaked"] is True
        assert data["total_findings"] == 1
        assert data["findings"][0]["finding_type"] == "IBAN"


@pytest.mark.asyncio
async def test_api_inspect_clean():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {"text": "Safe informational announcement."}
        resp = await ac.post("/api/inspect", json=payload)
        assert resp.status_code == 200
        assert resp.json()["is_leaked"] is False


@pytest.mark.asyncio
async def test_api_redact_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        mock_stripe = f"sk_{'live'}_dummysecrettoken1234567890abcdef"
        payload = {
            "text": f"Stripe token {mock_stripe} was exposed",
            "mode": "PARTIAL_MASK"
        }
        resp = await ac.post("/api/redact", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "sk_live_XXXX" in data["redacted_text"]
        assert data["findings_count"] == 1


@pytest.mark.asyncio
async def test_api_stream_monitor_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/api/stream/monitor", json={"sample_count": 2})
        assert resp.status_code == 200
        data = resp.json()
        assert data["events_scanned"] >= 1


@pytest.mark.asyncio
async def test_api_audit_violations_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/audit/violations?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


@pytest.mark.asyncio
async def test_api_validation_error_empty_text():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/api/inspect", json={"text": ""})
        assert resp.status_code == 422
