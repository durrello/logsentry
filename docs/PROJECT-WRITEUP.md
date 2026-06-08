# LogSentry — Sensitive Data Detection in Application Logs

## Project Overview

In production environments, services generate millions of log lines daily. Developers accidentally log sensitive data — API keys, passwords, tokens, database credentials — creating serious security and compliance risks.

**LogSentry** is an event-driven, serverless pipeline that:
1. **Auto-subscribes** all CloudWatch log groups (zero manual config)
2. **Scans in real-time** for 12 sensitive patterns with entropy analysis
3. **Stores findings** in DynamoDB with deduplication and TTL
4. **Sends rate-limited alerts** via SNS (email, Slack, PagerDuty)
5. **Emits custom metrics** for monitoring and CloudWatch alarms
6. **Provides a dashboard** to view, filter, and resolve findings

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        APPLICATION SERVICES                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Service A│  │ Service B│  │ Service C│  │ Service N│              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
└───────┼──────────────┼──────────────┼──────────────┼───────────────────┘
        │              │              │              │
        ▼              ▼              ▼              ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     AWS CLOUDWATCH LOG GROUPS                           │
│              (Auto-subscribed via EventBridge + Lambda)                 │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │ Subscription Filter (auto-created)
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        KINESIS DATA STREAM                              │
│                 (real-time buffer, 24h retention)                       │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │ Event Source Mapping (batch=100)
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      LAMBDA: LOG SCANNER (zip deploy)                   │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │  12 Detection Patterns + Shannon Entropy Analysis:            │     │
│  │  • AWS Keys, Stripe Keys, GitHub Tokens, Slack Tokens        │     │
│  │  • Passwords, DB URLs, Private Keys, JWTs, Bearer Tokens     │     │
│  │  • Generic API Keys, Generic Secrets                          │     │
│  └──────────────────────────────────────────────────────────────┘     │
│              │                    │                  │                  │
│              ▼                    ▼                  ▼                  │
│   ┌──────────────────┐  ┌───────────────┐  ┌──────────────────┐      │
│   │   DynamoDB        │  │  SNS Topic    │  │  CloudWatch      │      │
│   │   (TTL + GSI)     │  │  (rate-limit) │  │  (custom metrics)│      │
│   └──────────────────┘  └───────┬───────┘  └──────────────────┘      │
│                                  │                                     │
│   ┌──────────────────┐          │          ┌──────────────────┐       │
│   │   SQS DLQ         │          │         │  CW Alarms        │      │
│   │   (14-day retain) │          │         │  (errors+critical)│      │
│   └──────────────────┘          │          └──────────────────┘       │
└──────────────────────────────────┼─────────────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             ┌────────────┐ ┌────────────┐ ┌────────────┐
             │   Slack    │ │   Email    │ │ PagerDuty  │
             └────────────┘ └────────────┘ └────────────┘
```

---

## Day-to-Day Use Case

1. **Developer pushes code** that accidentally logs an API key in debug output
2. **Service generates logs** → CloudWatch → Kinesis → Lambda scanner (all automatic)
3. **Scanner detects** `sk_live_51HqS9RJ7sK4x8Yd...` in the log line
4. **Custom metric emitted** → CloudWatch alarm fires
5. **Rate-limited alert** → Email/Slack: "🚨 Stripe API key detected in payment-service"
6. **Engineer opens dashboard** → sees finding → clicks "Resolve"
7. **Engineer fixes** the code, rotates the credential
8. **Finding auto-expires** from DynamoDB after 90 days (TTL)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Detection Engine | Python 3.11 (Lambda) — regex + Shannon entropy |
| Log Ingestion | CloudWatch Subscription Filters → Kinesis |
| Auto-Subscribe | EventBridge (CloudTrail) + Scheduled Lambda (5-min fallback) |
| Storage | DynamoDB (findings, GSI on severity, TTL for auto-expiry) |
| Notifications | SNS → Email / Slack / PagerDuty (rate-limited) |
| Dead Letter Queue | SQS (14-day retention for failed events) |
| Monitoring | CloudWatch custom metrics (LogSentry namespace) + alarms |
| Dashboard | Flask + vanilla JS (demo mode + live DynamoDB mode) |
| IaC | Terraform (all resources, including state backend) |
| CI/CD | GitHub Actions + GitLab CI (test → scan → deploy zip) |
| Security | Trivy scanning, tfsec, IAM least-privilege, encrypted DynamoDB |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Zip deploy (not Docker/ECR) | Only dependency is boto3 (in Lambda runtime). Zip = faster cold start, simpler CI, smaller artifact |
| Kinesis (not SQS) | Ordered processing, replay capability, fan-out to multiple consumers |
| DynamoDB (not RDS) | Serverless, auto-scaling, pay-per-request, built-in TTL |
| Lazy boto3 initialization | Tests can import handler without AWS credentials |
| EventBridge + scheduled scan | Works with or without CloudTrail enabled |
| Rate-limited alerts | Prevents notification storms when a service dumps thousands of secrets |
| Deterministic finding IDs | Deduplication — same secret in same log group = same finding |

---

## Requirements Mapping (DevOps Project)

| # | Requirement | Implementation |
|---|---|---|
| 1 | Containerization | Lambda zip deploy (no Docker needed — simpler, faster) |
| 2 | Dev & Prod | Separate environments via Terraform variables (`terraform.tfvars.dev/prod`) |
| 3 | Tests | 20 unit tests covering detection, entropy, masking, structure |
| 4 | Orchestration | Event-driven (Kinesis → Lambda), auto-subscribe (EventBridge) |
| 5 | CI/CD | GitHub Actions: test → trivy → deploy. GitLab CI mirror available |
| 6 | IaC | Terraform: Kinesis, Lambda, DynamoDB, SNS, SQS, IAM, CloudWatch, EventBridge |
| 7 | Monitoring | Custom CloudWatch metrics (findings/severity), alarms, dashboard |
| 8 | Security | Trivy, tfsec, IAM roles, encrypted storage, no hardcoded secrets |
| 9 | DR | PITR (DynamoDB), S3 versioning (state), DLQ (failed events), 24h Kinesis retention |
| 10 | Docs | README, SETUP.md, PROJECT-WRITEUP.md |

---

## What Makes This Project Stand Out

- **Solves a real security problem** — secret leakage in logs is a top OWASP concern
- **Event-driven serverless** — Lambda, Kinesis, EventBridge, SNS (not just static web apps)
- **Zero-config monitoring** — auto-subscribes all log groups, no manual setup per service
- **Production-grade patterns** — DLQ, retries, idempotency, rate limiting, TTL, deduplication
- **Full observability** — custom metrics, alarms, dashboard with filtering and resolution
- **Simple deployment** — no Docker, no Kubernetes, just `terraform apply` and done
- **Cost-effective** — all serverless, pay only for what you use

---

## Metrics & Observability

| Metric | Namespace | Purpose |
|---|---|---|
| `FindingsDetected` | LogSentry | Total findings per invocation |
| `FindingsDetected` (by severity) | LogSentry | Critical/High/Medium breakdown |
| `NewFindings` | LogSentry | Deduplicated new findings |
| Lambda `Errors` | AWS/Lambda | Scanner failure rate |
| Lambda `Duration` | AWS/Lambda | Processing time |
| Lambda `Invocations` | AWS/Lambda | Event throughput |

---

## Security Controls

1. **IAM least-privilege** — each Lambda has only the permissions it needs
2. **Encrypted at rest** — DynamoDB server-side encryption
3. **No secrets in code** — all config via environment variables set by Terraform
4. **Secret masking** — findings store only masked values (first 4 + last 4 chars)
5. **DLQ for audit** — failed events preserved for 14 days
6. **Trivy + tfsec** — dependency and IaC scanning in CI
7. **Rate-limited alerts** — prevents information leakage via alert flooding

---

## Author

**Durrell Gemuh** — DevOps & Cloud Infrastructure Engineer

- Website: https://durrellgemuh.com
- GitHub: [@durrello](https://github.com/durrello)
