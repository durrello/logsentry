# LogSentry — Sensitive Data Detection in Application Logs

## Project Idea

In real-world production environments, teams run dozens of microservices that generate millions of log lines daily. Developers accidentally log sensitive data — API keys, passwords, tokens, database credentials, PII — creating serious security and compliance risks.

**LogSentry** is a log-scanning pipeline that:
1. **Ingests logs** from multiple services (via CloudWatch, Fluentd, or direct stream)
2. **Scans in real-time** for sensitive patterns (API keys, passwords, JWTs, AWS credentials, etc.)
3. **Sends alerts** (Slack, email, PagerDuty) when secrets are detected
4. **Provides a dashboard** to view, acknowledge, and remediate findings
5. **Offers remediation actions** — mask the secret in logs, rotate/regenerate the credential, or suppress the log source

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        APPLICATION SERVICES                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ Service A│  │ Service B│  │ Service C│  │ Service N│               │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘               │
│       │              │              │              │                     │
└───────┼──────────────┼──────────────┼──────────────┼────────────────────┘
        │              │              │              │
        ▼              ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     AWS CLOUDWATCH LOG GROUPS                            │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ CloudWatch Subscription Filter
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        KINESIS DATA STREAM                               │
│                    (real-time log ingestion)                             │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      LAMBDA: LOG SCANNER                                 │
│  ┌──────────────────────────────────────────────────────────────┐       │
│  │  Pattern Engine:                                              │       │
│  │  • AWS Access Keys (AKIA...)                                  │       │
│  │  • API Keys / Tokens (Bearer, sk_live_, etc.)                 │       │
│  │  • Passwords in key=value or JSON                             │       │
│  │  • JWTs (eyJ...)                                              │       │
│  │  • Database connection strings                                │       │
│  │  • PII (emails, SSNs, credit cards)                           │       │
│  └──────────────────────────────────────────────────────────────┘       │
│                         │                                               │
│              ┌──────────┴──────────┐                                    │
│              ▼                     ▼                                     │
│    ┌─────────────────┐   ┌─────────────────┐                           │
│    │  DynamoDB:       │   │  SNS Topic:     │                           │
│    │  Store finding   │   │  Send alert     │                           │
│    └─────────────────┘   └────────┬────────┘                           │
│                                    │                                    │
└────────────────────────────────────┼────────────────────────────────────┘
                                     │
                      ┌──────────────┼──────────────┐
                      ▼              ▼              ▼
              ┌─────────────┐ ┌──────────┐ ┌──────────────┐
              │    Slack    │ │  Email   │ │  PagerDuty   │
              └─────────────┘ └──────────┘ └──────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                      API GATEWAY + LAMBDA: DASHBOARD API                 │
│  GET  /findings          — list all findings                            │
│  GET  /findings/:id      — detail view                                  │
│  POST /findings/:id/ack  — acknowledge                                  │
│  POST /findings/:id/mask — mask secret in logs                          │
│  POST /findings/:id/rotate — trigger credential rotation                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Day-to-Day Use Case

1. **Developer pushes code** that accidentally logs an API key in debug output
2. **Service generates logs** → CloudWatch → Kinesis → Lambda scanner
3. **Scanner detects** the pattern `pk_test_FAKE00000000000000000000` in the log line
4. **Alert fires** → Slack message: "⚠️ API key detected in logs from payment-service (us-east-1)"
5. **DevOps engineer** opens the dashboard, sees the finding, clicks "Rotate" to regenerate the Stripe key
6. **Engineer fixes** the application code to stop logging the value
7. **Finding marked resolved** — audit trail preserved

---

## Tech Stack

| Layer | Technology |
|---|---|
| Log Ingestion | AWS CloudWatch + Kinesis Data Stream |
| Detection Engine | AWS Lambda (Python) with regex + entropy analysis |
| Storage | DynamoDB (findings), S3 (raw log samples) |
| Notifications | SNS → Slack/Email/PagerDuty |
| Dashboard API | API Gateway + Lambda |
| Dashboard UI | React (Next.js) |
| IaC | Terraform |
| CI/CD | GitHub Actions + GitLab CI |
| Container | Docker (for local dev + dashboard) |
| Orchestration | EKS (dashboard + sample services) |
| Monitoring | Prometheus + Grafana |
| Security | IAM least-privilege, encrypted DynamoDB, Trivy scanning |

---

## Requirements Mapping (DevOps Project)

| # | Requirement | Implementation |
|---|---|---|
| 1 | Docker | Multi-stage Dockerfile for dashboard + scanner local dev |
| 2 | Dev & Prod | Separate AWS accounts/environments via Terraform workspaces |
| 3 | Tests | Unit tests (pattern detection), integration tests (Lambda), E2E (full pipeline) |
| 4 | Kubernetes | Dashboard deployed on EKS, sample log-generating services on EKS |
| 5 | CI/CD | GitHub Actions: test → scan → build → push → deploy (app + infra) |
| 6 | IaC | Terraform: Kinesis, Lambda, DynamoDB, SNS, API Gateway, EKS, VPC |
| 7 | Monitoring | Prometheus metrics on detection rate, false positives, latency |
| 8 | Security | Trivy, no hardcoded secrets, IAM roles, encrypted storage |
| 9 | DR | DynamoDB point-in-time recovery, Lambda versioning, Terraform state in S3 |
| 10 | Docs | This document + README + architecture diagram |

---

## What Makes This Project Stand Out

- **Solves a real security problem** — secret leakage in logs is a top OWASP concern
- **Event-driven serverless** — demonstrates Lambda, Kinesis, SNS (not just static web apps)
- **Full observability pipeline** — ingestion → detection → notification → remediation
- **Production-grade patterns** — DLQ, retries, idempotency, at-least-once processing
- **Multi-team relevance** — useful for Security, DevOps, SRE, and Development teams
