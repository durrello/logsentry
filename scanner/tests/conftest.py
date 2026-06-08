"""Pytest configuration."""
import os
os.environ["FINDINGS_TABLE"] = "logsentry-findings-test"
os.environ["SNS_TOPIC_ARN"] = ""
os.environ["ENVIRONMENT"] = "test"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
