# LogSentry — Sensitive Data Detection in Application Logs

A serverless log-scanning pipeline that detects secrets, credentials, and sensitive data leaked into application logs. Built with AWS Lambda, Kinesis, DynamoDB, and SNS — deployed via Terraform with full CI/CD.

---

## Problem

Services generate millions of log lines daily. Developers accidentally log passwords, API keys, tokens, and PII. This creates security breaches and compliance violations. LogSentry catches these leaks in real-time and alerts your team to remediate.

---

## Architecture

```
Services → CloudWatch → Kinesis Stream → Lambda Scanner → DynamoDB (findings)
                                                       → SNS (alerts → Slack/Email)
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
│            (Subscription Filters → Kinesis)                         │
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
│              │                              │                       │
│              ▼                              ▼                       │
│   ┌──────────────────┐          ┌──────────────────┐              │
│   │   DynamoDB        │          │   SNS Topic       │              │
│   │   (store finding) │          │   (send alert)    │              │
│   └──────────────────┘          └────────┬─────────┘              │
│                                           │                        │
│   ┌──────────────────┐                    │                        │
│   │   SQS DLQ         │                   │                        │
│   │   (failed events) │                   │                        │
│   └──────────────────┘                    │                        │
└───────────────────────────────────────────┼────────────────────────┘
                                            │
                         ┌──────────────────┼──────────────────┐
                         ▼                  ▼                  ▼
                  ┌────────────┐    ┌────────────┐    ┌────────────┐
                  │   Slack    │    │   Email    │    │ PagerDuty  │
                  └────────────┘    └────────────┘    └────────────┘
```

---

## Detected Patterns

| Pattern | Example | Severity |
|---|---|---|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | Critical |
| Password in logs | `password=MySecret123` | Critical |
| Database URL | `postgres://user:pass@host/db` | Critical |
| Private Key | `-----BEGIN RSA PRIVATE KEY-----` | Critical |
| Stripe Key | `pk_test_FAKE00000000000000000000` | Critical |
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
| Storage | DynamoDB (findings, GSI on severity) |
| Notifications | SNS → Email / Slack / PagerDuty |
| Dead Letter Queue | SQS (failed processing retry) |
| Container Registry | AWS ECR (Lambda container image) |
| IaC | Terraform (Kinesis, Lambda, DynamoDB, SNS, ECR, IAM, SQS) |
| CI/CD | GitHub Actions + GitLab CI (test → scan → build → deploy) |
| Security | Trivy scanning, tfsec, IAM least-privilege, encrypted DynamoDB |

---

## Project Structure

```
logsentry/
├── scanner/                    # Lambda function (Python)
│   ├── handler.py              # Main detection logic (12 patterns)
│   ├── requirements.txt
│   ├── Dockerfile              # Lambda container image
│   └── tests/
│       ├── conftest.py
│       └── test_scanner.py     # 20 unit tests
├── terraform/                  # Infrastructure as Code
│   ├── main.tf                 # Kinesis + Lambda + DynamoDB + SNS + ECR + SQS + IAM
│   ├── variables.tf
│   ├── outputs.tf
│   ├── terraform.tfvars.dev
│   └── terraform.tfvars.prod
├── .github/workflows/
│   ├── ci-cd.yml               # App: test → trivy → build ECR → deploy Lambda
│   └── infra.yml               # Infra: fmt → validate → tfsec → plan → apply
├── .gitlab-ci.yml              # GitLab CI equivalent (app + infra)
├── docs/
│   └── PROJECT-WRITEUP.md     # Detailed project design document
├── Makefile                    # Dev shortcuts
├── .gitignore
└── README.md
```

---

## Setup & Deploy

### Prerequisites

- AWS CLI configured (`aws configure`)
- Terraform >= 1.5
- Python 3.11+
- Docker

### 1. Run tests locally

```bash
make test
```

### 2. Build scanner image

```bash
make build
```

### 3. Deploy infrastructure

```bash
make tf-init
make tf-plan-dev
make tf-apply-dev
```

### 4. Push scanner image to ECR

```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com
docker tag logsentry-scanner:latest <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/logsentry-scanner-dev:latest
docker push <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/logsentry-scanner-dev:latest
```

### 5. Subscribe a log group

```bash
aws logs put-subscription-filter \
  --log-group-name /your/service/logs \
  --filter-name logsentry \
  --filter-pattern "" \
  --destination-arn <KINESIS_STREAM_ARN> \
  --role-arn <CW_TO_KINESIS_ROLE_ARN>
```

---

## CI/CD Pipeline

```
Push → Tests (pytest) → Security Scan (Trivy) → Build Docker → Push ECR → Update Lambda
```

- **Dev branch** → auto-deploy
- **Main branch** → manual approval for prod
- **Terraform changes** → separate infra pipeline (plan → tfsec → apply)

---

## Security (DevSecOps)

1. **Trivy filesystem scan** — scans Python dependencies for CVEs
2. **tfsec** — scans Terraform for misconfigurations
3. **ECR image scanning** — scan-on-push enabled
4. **IAM least privilege** — Lambda role has only required permissions
5. **Encrypted DynamoDB** — server-side encryption enabled
6. **No hardcoded secrets** — all via environment variables / Terraform
7. **Dead Letter Queue** — failed events preserved for audit

---

## Monitoring

- **CloudWatch Metrics** — Lambda invocations, errors, duration
- **DynamoDB Metrics** — read/write capacity, throttles
- **Custom Metrics** — findings per severity, detection rate, false positives
- **CloudWatch Alarms** — alert if scanner error rate > 5%

---

## Disaster Recovery

| Component | Recovery Strategy |
|---|---|
| DynamoDB findings | Point-in-time recovery enabled (35 days) |
| Lambda function | Versioned, rollback via `aws lambda update-function-code` |
| Terraform state | S3 with versioning + DynamoDB lock |
| Kinesis stream | 24h retention, replay from last checkpoint |
| Failed events | SQS DLQ with 14-day retention |
| Full infra rebuild | `terraform apply` reproduces everything |

---

## Environment Differences

| Setting | Dev | Prod |
|---|---|---|
| Kinesis shards | 1 | 2 |
| ECR force_delete | true | false |
| SNS email alerts | disabled | enabled |
| DLQ retention | 14 days | 14 days |
| Lambda memory | 256 MB | 256 MB |

---

## Author

**Durrell Gemuh** — DevOps & Cloud Infrastructure Engineer

- Website: https://durrellgemuh.com
- GitHub: [@durrello](https://github.com/durrello)
