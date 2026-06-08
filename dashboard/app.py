"""
LogSentry Dashboard — Flask app that works locally (demo mode) and live (DynamoDB).
Serves a findings dashboard with stats, filtering, and real-time scanning demo.

Usage:
  Local demo:  python app.py                         (uses sample data)
  Live mode:   LOGSENTRY_MODE=live python app.py     (reads from DynamoDB)
"""
import os
import sys
import json
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, jsonify, request

# Add scanner module to path for live scanning demo
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

app = Flask(__name__)

MODE = os.environ.get("LOGSENTRY_MODE", "demo")  # "demo" or "live"
TABLE_NAME = os.environ.get("FINDINGS_TABLE", "logsentry-findings")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


# === Sample data for demo mode ===
SAMPLE_FINDINGS = [
    {
        "finding_id": "9178cb695c453fa8",
        "pattern_name": "aws_access_key",
        "severity": "critical",
        "description": "AWS Access Key ID detected",
        "log_group": "/app/payment-service",
        "log_stream": "i-0abcdef1234567890",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        "matched_value_masked": "AKIA************MPLE",
        "context": "ERROR Auth failed using key AKIAIOSFODNN7EXAMPLE for service call",
        "environment": "production",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
    },
    {
        "finding_id": "f2c01244b3f1405d",
        "pattern_name": "password_in_log",
        "severity": "critical",
        "description": "Password value logged",
        "log_group": "/app/auth-service",
        "log_stream": "i-0fedcba9876543210",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=12)).isoformat(),
        "matched_value_masked": "pass****************ret!",
        "context": "DEBUG Connecting with password=SuperSecret! to auth backend",
        "environment": "production",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(minutes=12)).isoformat(),
    },
    {
        "finding_id": "ed3d420e4c2b5ea5",
        "pattern_name": "database_url",
        "severity": "critical",
        "description": "Database connection string with credentials",
        "log_group": "/app/order-service",
        "log_stream": "i-0111222333444555",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=23)).isoformat(),
        "matched_value_masked": "post**********************************************ders",
        "context": "DEBUG Connecting to postgres://admin:p4ssw0rd@db.prod.internal:5432/orders",
        "environment": "production",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(minutes=23)).isoformat(),
    },
    {
        "finding_id": "fed286f0fb608195",
        "pattern_name": "jwt_token",
        "severity": "high",
        "description": "JWT token detected",
        "log_group": "/app/api-gateway",
        "log_stream": "i-0aaa111bbb222ccc",
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "matched_value_masked": "eyJh****************************sR8U",
        "context": "INFO Auth token: eyJhbGciOiJIUzI1NiIs...",
        "environment": "staging",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
    },
    {
        "finding_id": "1f668235b8f0681c",
        "pattern_name": "github_token",
        "severity": "critical",
        "description": "GitHub personal access token detected",
        "log_group": "/app/ci-runner",
        "log_stream": "i-0ddd444eee555fff",
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "matched_value_masked": "ghp_********************************ghij",
        "context": "WARN Using token ghp_ABCDEFGHIJKLMNOP... for GitHub API call",
        "environment": "production",
        "status": "resolved",
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    },
    {
        "finding_id": "bb16d5179fb270b3",
        "pattern_name": "stripe_key",
        "severity": "critical",
        "description": "Stripe API key detected",
        "log_group": "/app/payment-service",
        "log_stream": "i-0abcdef1234567890",
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
        "matched_value_masked": "sk_l************************ey99",
        "context": "ERROR Payment retry with sk_live_... failed",
        "environment": "production",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
    },
    {
        "finding_id": "defa5c0cf31175c9",
        "pattern_name": "generic_api_key",
        "severity": "high",
        "description": "Generic API key in key=value format",
        "log_group": "/app/notification-service",
        "log_stream": "i-0ggg666hhh777iii",
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
        "matched_value_masked": "api_*****************************************long",
        "context": "DEBUG api_key=sk_test_BQokikJOvBiI... set for sendgrid",
        "environment": "staging",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
    },
    {
        "finding_id": "a1b2c3d4e5f60001",
        "pattern_name": "slack_token",
        "severity": "high",
        "description": "Slack token detected",
        "log_group": "/app/bot-service",
        "log_stream": "i-0jjj888kkk999lll",
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat(),
        "matched_value_masked": "xoxb****************************cdef",
        "context": "INFO Slack bot connected with xoxb-1234-5678-abcdef...",
        "environment": "production",
        "status": "resolved",
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat(),
    },
    {
        "finding_id": "a1b2c3d4e5f60002",
        "pattern_name": "generic_secret",
        "severity": "medium",
        "description": "Generic secret pattern detected",
        "log_group": "/app/config-service",
        "log_stream": "i-0mmm000nnn111ooo",
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat(),
        "matched_value_masked": "secr********************val1",
        "context": "DEBUG Loading secret=AbCdEfGhIjKlMnOpQrSt from vault",
        "environment": "development",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat(),
    },
    {
        "finding_id": "a1b2c3d4e5f60003",
        "pattern_name": "private_key",
        "severity": "critical",
        "description": "Private key detected in logs",
        "log_group": "/app/ssh-service",
        "log_stream": "i-0ppp222qqq333rrr",
        "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "matched_value_masked": "----****----",
        "context": "ERROR -----BEGIN RSA PRIVATE KEY----- found in config dump",
        "environment": "production",
        "status": "open",
        "detected_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
    },
]


def get_findings_demo(severity=None, status=None):
    """Return sample findings with optional filters."""
    findings = SAMPLE_FINDINGS
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    if status:
        findings = [f for f in findings if f["status"] == status]
    return findings


def get_findings_live(severity=None, status=None):
    """Fetch findings from DynamoDB."""
    import boto3
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = dynamodb.Table(TABLE_NAME)

    if severity:
        response = table.query(
            IndexName="severity-index",
            KeyConditionExpression="severity = :sev",
            ExpressionAttributeValues={":sev": severity},
        )
    else:
        response = table.scan()

    findings = response.get("Items", [])
    if status:
        findings = [f for f in findings if f.get("status") == status]
    return sorted(findings, key=lambda x: x.get("detected_at", ""), reverse=True)


def get_findings(**kwargs):
    if MODE == "live":
        return get_findings_live(**kwargs)
    return get_findings_demo(**kwargs)


# === Routes ===

@app.route("/")
def index():
    return render_template("index.html", mode=MODE)


@app.route("/api/findings")
def api_findings():
    severity = request.args.get("severity")
    status = request.args.get("status")
    findings = get_findings(severity=severity, status=status)
    return jsonify(findings)


@app.route("/api/stats")
def api_stats():
    findings = get_findings()
    stats = {
        "total": len(findings),
        "critical": len([f for f in findings if f["severity"] == "critical"]),
        "high": len([f for f in findings if f["severity"] == "high"]),
        "medium": len([f for f in findings if f["severity"] == "medium"]),
        "open": len([f for f in findings if f["status"] == "open"]),
        "resolved": len([f for f in findings if f["status"] == "resolved"]),
        "by_pattern": {},
        "by_service": {},
    }
    for f in findings:
        pattern = f["pattern_name"]
        stats["by_pattern"][pattern] = stats["by_pattern"].get(pattern, 0) + 1
        service = f["log_group"]
        stats["by_service"][service] = stats["by_service"].get(service, 0) + 1
    return jsonify(stats)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Live scan endpoint — paste a log line and get findings back."""
    from handler import scan_log_event
    data = request.get_json()
    log_line = data.get("log_line", "")
    log_event = {"message": log_line, "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000)}
    findings = scan_log_event(log_event, "/demo/live-scan", "dashboard")
    return jsonify({"findings": findings, "scanned": log_line[:100]})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'='*60}")
    print(f"  LogSentry Dashboard")
    print(f"  Mode: {'📡 LIVE (DynamoDB)' if MODE == 'live' else '🎮 DEMO (sample data)'}")
    print(f"  URL:  http://localhost:{port}")
    print(f"{'='*60}\n")
    app.run(host="0.0.0.0", port=port, debug=True)
