"""
LogSentry Scanner — AWS Lambda function
Detects sensitive data patterns in CloudWatch log events streamed via Kinesis.
"""
import json
import os
import re
import base64
import gzip
import hashlib
import time
import boto3
from datetime import datetime

# Configuration
TABLE_NAME = os.environ.get("FINDINGS_TABLE", "logsentry-findings")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

# Lazy-initialized AWS clients (avoids errors when importing in test/CI without AWS config)
_dynamodb = None
_sns = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def _get_sns():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns

# Sensitive data patterns
PATTERNS = {
    "aws_access_key": {
        "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
        "severity": "critical",
        "description": "AWS Access Key ID detected",
    },
    "aws_secret_key": {
        "regex": r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        "severity": "critical",
        "description": "Potential AWS Secret Access Key",
        "requires_context": True,
    },
    "generic_api_key": {
        "regex": r"(?i)(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,64})['\"]?",
        "severity": "high",
        "description": "Generic API key in key=value format",
    },
    "bearer_token": {
        "regex": r"Bearer\s+([A-Za-z0-9\-_\.]{20,})",
        "severity": "high",
        "description": "Bearer token detected",
    },
    "jwt_token": {
        "regex": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
        "description": "JWT token detected",
    },
    "password_in_log": {
        "regex": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,64})['\"]?",
        "severity": "critical",
        "description": "Password value logged",
    },
    "database_url": {
        "regex": r"(?:mysql|postgres|postgresql|mongodb|redis):\/\/[^\s]{10,}",
        "severity": "critical",
        "description": "Database connection string with credentials",
    },
    "private_key": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private key detected in logs",
    },
    "stripe_key": {
        "regex": r"(?:sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9]{20,}",
        "severity": "critical",
        "description": "Stripe API key detected",
    },
    "slack_token": {
        "regex": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,}",
        "severity": "high",
        "description": "Slack token detected",
    },
    "github_token": {
        "regex": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "description": "GitHub personal access token detected",
    },
    "generic_secret": {
        "regex": r"(?i)(?:secret|token|credential)\s*[=:]\s*['\"]?([A-Za-z0-9_\-/+=]{16,})['\"]?",
        "severity": "medium",
        "description": "Generic secret pattern detected",
    },
}


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy to detect high-randomness strings (likely secrets)."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * (p_x and __import__("math").log2(p_x))
    return entropy


def mask_secret(value: str) -> str:
    """Mask a secret value for safe storage/display."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def generate_finding_id(log_group: str, pattern_name: str, matched_value: str) -> str:
    """Generate a deterministic finding ID for deduplication."""
    raw = f"{log_group}:{pattern_name}:{matched_value}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def scan_log_event(log_event: dict, log_group: str, log_stream: str) -> list:
    """Scan a single log event for sensitive patterns."""
    findings = []
    message = log_event.get("message", "")
    timestamp = log_event.get("timestamp", int(time.time() * 1000))

    for pattern_name, pattern_config in PATTERNS.items():
        matches = re.finditer(pattern_config["regex"], message)
        for match in matches:
            matched_value = match.group(0)

            # Skip low-entropy matches for patterns that need context
            if pattern_config.get("requires_context"):
                if calculate_entropy(matched_value) < 3.5:
                    continue

            finding = {
                "finding_id": generate_finding_id(log_group, pattern_name, matched_value),
                "pattern_name": pattern_name,
                "severity": pattern_config["severity"],
                "description": pattern_config["description"],
                "log_group": log_group,
                "log_stream": log_stream,
                "timestamp": datetime.utcfromtimestamp(timestamp / 1000).isoformat() + "Z",
                "matched_value_masked": mask_secret(matched_value),
                "context": message[:200],  # First 200 chars for context
                "environment": ENVIRONMENT,
                "status": "open",
                "detected_at": datetime.utcnow().isoformat() + "Z",
            }
            findings.append(finding)

    return findings


def store_finding(finding: dict) -> bool:
    """Store finding in DynamoDB (deduplicated by finding_id)."""
    table = _get_dynamodb().Table(TABLE_NAME)
    try:
        table.put_item(
            Item=finding,
            ConditionExpression="attribute_not_exists(finding_id)",
        )
        return True  # New finding
    except _get_dynamodb().meta.client.exceptions.ConditionalCheckFailedException:
        return False  # Already exists (duplicate)


def send_alert(finding: dict):
    """Send SNS notification for new findings."""
    if not SNS_TOPIC_ARN:
        return

    severity_emoji = {"critical": "🚨", "high": "⚠️", "medium": "📢"}.get(
        finding["severity"], "ℹ️"
    )

    message = (
        f"{severity_emoji} LogSentry Alert — {finding['severity'].upper()}\n\n"
        f"Pattern: {finding['description']}\n"
        f"Service: {finding['log_group']}\n"
        f"Value: {finding['matched_value_masked']}\n"
        f"Time: {finding['timestamp']}\n"
        f"Environment: {finding['environment']}\n\n"
        f"Context: {finding['context'][:100]}..."
    )

    _get_sns().publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[LogSentry] {finding['severity'].upper()}: {finding['description']}",
        Message=message,
    )


def handler(event, context):
    """
    Lambda handler — processes Kinesis records containing CloudWatch log events.
    Each Kinesis record contains a gzipped, base64-encoded CloudWatch log batch.
    """
    total_findings = 0
    new_findings = 0

    for record in event.get("Records", []):
        # Decode Kinesis record
        payload = base64.b64decode(record["kinesis"]["data"])
        log_data = json.loads(gzip.decompress(payload))

        log_group = log_data.get("logGroup", "unknown")
        log_stream = log_data.get("logStream", "unknown")
        log_events = log_data.get("logEvents", [])

        for log_event in log_events:
            findings = scan_log_event(log_event, log_group, log_stream)
            total_findings += len(findings)

            for finding in findings:
                is_new = store_finding(finding)
                if is_new:
                    new_findings += 1
                    send_alert(finding)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "records_processed": len(event.get("Records", [])),
            "total_findings": total_findings,
            "new_findings": new_findings,
        }),
    }
