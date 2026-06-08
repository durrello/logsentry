# LogSentry — Sensitive Data Detection in Application Logs

A serverless log-scanning pipeline that detects secrets, credentials, and sensitive data leaked into application logs. Built with AWS Lambda, Kinesis, DynamoDB, and SNS — deployed via Terraform with full CI/CD.

---

## Problem

Services generate millions of log lines daily. Developers accidentally log passwords, API keys, tokens, and PII. This creates security breaches and compliance violations. LogSentry catches these leaks in real-time and alerts your team to remediate.

---

## Architecture

```
Services → CloudWatch → [Auto-Subscribe] → Kinesis → Lambda Scanner → DynamoDB + SNS Alert
```

```
┌────────────────────────────────────────────────────────────────────┐
│                     APPLICATION SERVICES                            │
│  Service A  │  Service B  │  Service C  │  ...  │  Service N      │
└──────┬──────┴──────┬──────┴──────┬──────┴───────┴──────┬──────────┘
       │             │             │                      │
       ▼             ▼             ▼                      ▼
┌────────────────────────────────────────────────────────────────────┐
│               AWS CLOUDWATCH LOG GROUPS                             │
│         (Auto-subscribed by EventBridge + Lambda)                   │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│                    KINESIS DATA STREAM                              │
│               (real-time log event buffer)                          │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│                    LAMBDA: LOG SCANNER                              │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │  12 Detection Patterns:                                     │   │
│  │  • AWS Keys (AKIA...)     • Stripe keys (sk_live_)         │   │
│  │  • Passwords (pwd=...)    • GitHub tokens (ghp_)           │   │
│  │  • JWTs (eyJ...)          • Slack tokens (xox...)          │   │
│  │  • DB connection strings  • Private keys (-----BEGIN)      │   │
│  │  • Bearer tokens          • Generic secrets                │   │
│  │  + Shannon entropy analysis for low-false-positive results │   │
│  └────────────────────────────────────────────────────────────┘   │
│              │                    │                  │              │
│              ▼                    ▼                  ▼              │
│   ┌──────────────────┐  ┌───────────────┐  ┌──────────────────┐  │
│   │   DynamoDB        │  │  SNS Topic    │  │  CloudWatch      │  │
│   │   (findings+TTL)  │  │  (rate-limit) │  │  (custom metrics)│  │
│   └──────────────────┘  └───────┬───────┘  └──────────────────┘  │
│                                  │                                 │
│   ┌──────────────────┐          │                                 │
│   │   SQS DLQ         │          │                                │
│   │   (failed events) │          │                                │
│   └──────────────────┘          │                                 │
└──────────────────────────────────┼─────────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             ┌────────────┐ ┌────────────┐ ┌────────────┐
             │   Slack    │ │   Email    │ │ PagerDuty  │
             └────────────┘ └────────────┘ └────────────┘
```

---

## Key Features

- **Zero-config log monitoring** — new CloudWatch log groups are auto-subscribed (no manual setup)
- **12 detection patterns** with Shannon entropy analysis to reduce false positives
- **Real-time alerts** with rate limiting to prevent notification storms
- **Auto-expiring findings** — resolved items TTL after 90 days (configurable)
- **Custom CloudWatch metrics** — per-severity detection rates with alarms
- **Dashboard** — Flask web UI for viewing, filtering, and resolving findings
- **Live scanner** — paste any log line to test detection instantly

---

## Detected Patterns

| Pattern | Example | Severity |
|---|---|---|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | Critical |
| Password in logs | `password=MySecret123` | Critical |
| Database URL | `postgres://user:pass@host/db` | Critical |
| Private Key | `-----BEGIN RSA PRIVATE KEY-----` | Critical |
| Stripe Key | `sk_live_51HqS9RJ7sK4x8Yd...` | Critical |
| GitHub Token | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZab` | Critical |
| JWT Token | `eyJhbGciOiJIUzI1NiIs...` | High |
| Bearer Token | `Bearer eyJhbGci...` | High |
| Slack Token | `xoxb-1234-5678-abcdef` | High |
| Generic API Key | `api_key=abc123def456` | High |
| Generic Secret | `secret=longRandomValue` | Medium |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Detection Engine | Python 3.11 (Lambda) — regex + Shannon entropy |
| Log Ingestion | CloudWatch Subscription Filters → Kinesis |
| Auto-Subscribe | EventBridge + Lambda (event-driven + scheduled) |
| Storage | DynamoDB (findings, GSI on severity, TTL) |
| Notifications | SNS → Email / Slack / PagerDuty (rate-limited) |
| Dead Letter Queue | SQS (14-day retention) |
| Monitoring | CloudWatch custom metrics + alarms |
| Dashboard | Flask + vanilla JS (works local + live) |
| IaC | Terraform (all resources, zero manual setup) |
| CI/CD | GitHub Actions (test → trivy → deploy zip) |
| Security | Trivy, tfsec, IAM least-privilege, encrypted DynamoDB |

---

## Project Structure

```
logsentry/
├── scanner/                    # Lambda function (Python)
│   ├── handler.py              # Detection logic (12 patterns + entropy + metrics)
│   ├── requirements.txt        # boto3 (included in Lambda runtime)
│   └── tests/
│       ├── conftest.py
│       └── test_scanner.py     # 20 unit tests
├── dashboard/                  # Security dashboard (Flask)
│   ├── app.py                  # API + routes (demo + live mode)
│   ├── templates/index.html    # Dashboard UI
│   └── requirements.txt
├── terraform/                  # Infrastructure as Code
│   ├── main.tf                 # All AWS resources
│   ├── variables.tf            # Configuration
│   ├── outputs.tf              # Exported values
│   ├── terraform.tfvars.dev
│   ├── terraform.tfvars.prod
│   └── scripts/
│       └── subscribe_existing.py  # One-time existing log group subscription
├── .github/workflows/
│   ├── ci-cd.yml               # App: test → trivy → deploy Lambda (zip)
│   └── infra.yml               # Infra: fmt → validate → tfsec → plan → apply
├── .gitlab-ci.yml              # GitLab CI equivalent
├── docs/
│   ├── PROJECT-WRITEUP.md     # Design document
│   └── SETUP.md               # First-time deployment guide
├── Makefile                    # Dev shortcuts
└── README.md
```

---

## Quick Start

### Prerequisites

- AWS CLI configured (`aws sts get-caller-identity`)
- Terraform >= 1.5
- Python 3.11+

### 1. Run tests

```bash
make test
```

### 2. Deploy infrastructure

```bash
make tf-init
make tf-plan-dev
make tf-apply-dev
```

This deploys everything and auto-subscribes all existing log groups.

### 3. Deploy scanner

```bash
make deploy
```

### 4. Run dashboard

```bash
make dashboard-live
```

Open http://localhost:8080

> See [docs/SETUP.md](docs/SETUP.md) for detailed first-time setup including Terraform state bootstrap.

---

## CI/CD Pipeline

```
Push → Tests (pytest) → Security Scan (Trivy) → Deploy Lambda (zip)
```

- **Dev branch** → auto-deploy to dev environment
- **Main branch** → deploy to prod (with environment protection)
- **Terraform changes** → separate pipeline: fmt → validate → tfsec → plan → apply

---

## How Auto-Subscribe Works

| Trigger | Mechanism |
|---|---|
| New log group created | EventBridge → auto-subscribe Lambda (instant, requires CloudTrail) |
| Scheduled fallback | Every 5 minutes, scan for unsubscribed groups (no CloudTrail needed) |
| First deploy | `subscribe_existing.py` runs via Terraform local-exec |
| Excluded prefixes | `/aws/lambda/logsentry`, `/aws/cloudtrail`, `/aws/rds` (configurable) |

---

## Security (DevSecOps)

1. **Trivy filesystem scan** — scans dependencies for CVEs
2. **tfsec** — scans Terraform for misconfigurations
3. **IAM least privilege** — Lambda roles have only required permissions
4. **Encrypted DynamoDB** — server-side encryption enabled
5. **No hardcoded secrets** — all via environment variables / Terraform
6. **Dead Letter Queue** — failed events preserved for audit
7. **Alert rate limiting** — prevents notification storms (max 10/invocation)

---

## Monitoring & Alerting

| Metric | Namespace | Alarm |
|---|---|---|
| Lambda errors | AWS/Lambda | > 5 errors in 10 min → SNS |
| Findings detected (critical) | LogSentry | Any critical finding → SNS |
| Findings detected (per severity) | LogSentry | Custom dashboards |
| New findings | LogSentry | Trend monitoring |

---

## Disaster Recovery

| Component | Recovery Strategy |
|---|---|
| DynamoDB findings | Point-in-time recovery enabled (35 days) |
| Lambda function | Zip deployed, rollback via previous zip |
| Terraform state | S3 with versioning + DynamoDB lock |
| Kinesis stream | 24h retention, replay from last checkpoint |
| Failed events | SQS DLQ with 14-day retention |
| Resolved findings | Auto-expire via DynamoDB TTL (90 days) |
| Full infra rebuild | `terraform apply` reproduces everything |

---

## Configuration

| Variable | Description | Default |
|---|---|---|
| `environment` | `dev` or `prod` | `dev` |
| `alert_email` | Email for SNS alerts | `""` (disabled) |
| `log_group_exclude_prefixes` | Prefixes to skip | `/aws/lambda/logsentry,...` |
| `findings_ttl_days` | Days to keep resolved findings | `90` |
| `alert_rate_limit` | Max alerts per Lambda invocation | `10` |

---

## Environment Differences

| Setting | Dev | Prod |
|---|---|---|
| Kinesis shards | 1 | 2 |
| SNS email alerts | disabled | enabled |
| DLQ retention | 14 days | 14 days |
| Lambda memory | 256 MB | 256 MB |
| Findings TTL | 90 days | 90 days |

---

## Author

**Durrell Gemuh** — DevOps & Cloud Infrastructure Engineer

- Website: https://durrellgemuh.com
- GitHub: [@durrello](https://github.com/durrello)
