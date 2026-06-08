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
import math
from datetime import datetime, timezone, timedelta

# Configuration
TABLE_NAME = os.environ.get("FINDINGS_TABLE", "logsentry-findings")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
FINDINGS_TTL_DAYS = int(os.environ.get("FINDINGS_TTL_DAYS", "90"))
ALERT_RATE_LIMIT = int(os.environ.get("ALERT_RATE_LIMIT", "10"))

# Lazy-initialized AWS clients
_dynamodb = None
_sns = None
_cloudwatch = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        import boto3
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def _get_sns():
    global _sns
    if _sns is None:
        import boto3
        _sns = boto3.client("sns")
    return _sns


def _get_cloudwatch():
    global _cloudwatch
    if _cloudwatch is None:
        import boto3
        _cloudwatch = boto3.client("cloudwatch")
    return _cloudwatch


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
        entropy -= p_x * math.log2(p_x)
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

            now = datetime.now(timezone.utc)
            finding = {
                "finding_id": generate_finding_id(log_group, pattern_name, matched_value),
                "pattern_name": pattern_name,
                "severity": pattern_config["severity"],
                "description": pattern_config["description"],
                "log_group": log_group,
                "log_stream": log_stream,
                "timestamp": datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).isoformat(),
                "matched_value_masked": mask_secret(matched_value),
                "context": message[:200],
                "environment": ENVIRONMENT,
                "status": "open",
                "detected_at": now.isoformat(),
            }

            # TTL: set expiry for resolved findings (open findings don't expire)
            if FINDINGS_TTL_DAYS > 0:
                finding["expires_at"] = int((now + timedelta(days=FINDINGS_TTL_DAYS)).timestamp())

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


def emit_metrics(total_findings: int, new_findings: int, findings_by_severity: dict):
    """Emit custom CloudWatch metrics for monitoring."""
    try:
        metric_data = [
            {
                "MetricName": "FindingsDetected",
                "Value": total_findings,
                "Unit": "Count",
                "Dimensions": [{"Name": "Environment", "Value": ENVIRONMENT}],
            },
            {
                "MetricName": "NewFindings",
                "Value": new_findings,
                "Unit": "Count",
                "Dimensions": [{"Name": "Environment", "Value": ENVIRONMENT}],
            },
        ]

        # Per-severity metrics
        for severity, count in findings_by_severity.items():
            metric_data.append({
                "MetricName": "FindingsDetected",
                "Value": count,
                "Unit": "Count",
                "Dimensions": [
                    {"Name": "Environment", "Value": ENVIRONMENT},
                    {"Name": "Severity", "Value": severity},
                ],
            })

        _get_cloudwatch().put_metric_data(
            Namespace="LogSentry",
            MetricData=metric_data,
        )
    except Exception as e:
        print(f"Failed to emit metrics: {e}")


def handler(event, context):
    """
    Lambda handler — processes Kinesis records containing CloudWatch log events.
    Each Kinesis record contains a gzipped, base64-encoded CloudWatch log batch.
    """
    total_findings = 0
    new_findings = 0
    alerts_sent = 0
    findings_by_severity = {}

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
                # Track by severity
                sev = finding["severity"]
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

                is_new = store_finding(finding)
                if is_new:
                    new_findings += 1
                    # Rate-limit alerts to prevent storms
                    if alerts_sent < ALERT_RATE_LIMIT:
                        send_alert(finding)
                        alerts_sent += 1

    # Emit custom CloudWatch metrics
    if total_findings > 0:
        emit_metrics(total_findings, new_findings, findings_by_severity)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "records_processed": len(event.get("Records", [])),
            "total_findings": total_findings,
            "new_findings": new_findings,
            "alerts_sent": alerts_sent,
        }),
    }
