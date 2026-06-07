"""Unit tests for the LogSentry scanner."""
import pytest
import json
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from handler import (
    scan_log_event,
    calculate_entropy,
    mask_secret,
    generate_finding_id,
    PATTERNS,
)


class TestPatternDetection:
    """Test sensitive data pattern matching."""

    def test_detect_aws_access_key(self):
        log_event = {"message": "Using key AKIAIOSFODNN7EXAMPLE for auth", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/service-a", "stream-1")
        assert len(findings) >= 1
        assert any(f["pattern_name"] == "aws_access_key" for f in findings)
        assert findings[0]["severity"] == "critical"

    def test_detect_password_in_log(self):
        log_event = {"message": 'Connecting with password=SuperSecret123!', "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/service-b", "stream-1")
        assert len(findings) >= 1
        assert any(f["pattern_name"] == "password_in_log" for f in findings)

    def test_detect_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        log_event = {"message": f"Auth token: {jwt}", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/auth", "stream-1")
        assert len(findings) >= 1
        assert any(f["pattern_name"] == "jwt_token" for f in findings)

    def test_detect_stripe_key(self):
        log_event = {"message": "Payment processed with sk_live_EXAMPLE_KEY_REDACTED_000", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/payments", "stream-1")
        assert len(findings) >= 1
        assert any(f["pattern_name"] == "stripe_key" for f in findings)

    def test_detect_database_url(self):
        log_event = {"message": "Connecting to postgres://admin:password123@db.example.com:5432/mydb", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/backend", "stream-1")
        assert len(findings) >= 1
        assert any(f["pattern_name"] == "database_url" for f in findings)

    def test_detect_github_token(self):
        log_event = {"message": "Using token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/ci", "stream-1")
        assert len(findings) >= 1
        assert any(f["pattern_name"] == "github_token" for f in findings)

    def test_detect_bearer_token(self):
        log_event = {"message": "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/api", "stream-1")
        assert len(findings) >= 1

    def test_detect_generic_api_key(self):
        log_event = {"message": 'api_key=sk_test_BQokikJOvBiI2HlWgH4olfQ2extra', "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/config", "stream-1")
        assert len(findings) >= 1

    def test_no_false_positive_normal_log(self):
        log_event = {"message": "INFO: User logged in successfully at 2024-01-15 10:30:00", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/auth", "stream-1")
        assert len(findings) == 0

    def test_no_false_positive_short_values(self):
        log_event = {"message": "password=***", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/test", "stream-1")
        # Should not match masked values
        pwd_findings = [f for f in findings if f["pattern_name"] == "password_in_log"]
        assert len(pwd_findings) == 0

    def test_multiple_findings_in_one_line(self):
        log_event = {
            "message": "key=AKIAIOSFODNN7EXAMPLE password=MySecret123!",
            "timestamp": 1700000000000,
        }
        findings = scan_log_event(log_event, "/app/multi", "stream-1")
        assert len(findings) >= 2


class TestUtilityFunctions:
    """Test helper functions."""

    def test_entropy_high_randomness(self):
        # Random-looking string should have high entropy
        entropy = calculate_entropy("aB3$kL9mNpQrStUvWxYz")
        assert entropy > 3.5

    def test_entropy_low_randomness(self):
        # Repeated chars = low entropy
        entropy = calculate_entropy("aaaaaaaaaa")
        assert entropy < 1.0

    def test_mask_secret_long(self):
        masked = mask_secret("sk_live_EXAMPLE_KEY_REDACTED_000")
        assert masked.startswith("sk_l")
        assert masked.endswith("7dc")
        assert "****" in masked or "*" in masked

    def test_mask_secret_short(self):
        masked = mask_secret("short")
        assert masked == "****"

    def test_finding_id_deterministic(self):
        id1 = generate_finding_id("/app/svc", "aws_key", "AKIATEST")
        id2 = generate_finding_id("/app/svc", "aws_key", "AKIATEST")
        assert id1 == id2

    def test_finding_id_unique(self):
        id1 = generate_finding_id("/app/svc", "aws_key", "AKIATEST1")
        id2 = generate_finding_id("/app/svc", "aws_key", "AKIATEST2")
        assert id1 != id2


class TestFindingStructure:
    """Test that findings have correct structure."""

    def test_finding_has_required_fields(self):
        log_event = {"message": "token AKIAIOSFODNN7EXAMPLE leaked", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/test", "stream-1")
        assert len(findings) >= 1
        finding = findings[0]
        required_fields = [
            "finding_id", "pattern_name", "severity", "description",
            "log_group", "log_stream", "timestamp", "matched_value_masked",
            "context", "environment", "status", "detected_at",
        ]
        for field in required_fields:
            assert field in finding, f"Missing field: {field}"

    def test_finding_status_is_open(self):
        log_event = {"message": "AKIAIOSFODNN7EXAMPLE", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/test", "stream-1")
        assert findings[0]["status"] == "open"

    def test_finding_value_is_masked(self):
        log_event = {"message": "AKIAIOSFODNN7EXAMPLE", "timestamp": 1700000000000}
        findings = scan_log_event(log_event, "/app/test", "stream-1")
        # The full key should NOT be in the masked value
        assert "AKIAIOSFODNN7EXAMPLE" != findings[0]["matched_value_masked"]
