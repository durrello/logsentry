# LogSentry — First-Time Setup Guide

This guide covers deploying LogSentry from scratch. After setup, **all CloudWatch log groups are automatically monitored** — no manual steps needed for new services.

---

## Prerequisites

| Tool | Version | Check |
|---|---|---|
| AWS CLI | v2+ | `aws --version` |
| Terraform | >= 1.5 | `terraform --version` |
| Python | 3.11+ | `python3 --version` |

AWS CLI must be configured with credentials that have admin access:
```bash
aws sts get-caller-identity
```

> Docker is NOT required. LogSentry uses zip deployment for Lambda.

---

## How It Works (After Setup)

```
Any Service → CloudWatch Logs → [Auto-Subscribe] → Kinesis → Lambda Scanner → DynamoDB + SNS
```

- **New log groups** are auto-subscribed via EventBridge + scheduled scan (every 5 min)
- **Existing log groups** are subscribed during first `terraform apply`
- **No manual intervention** needed after initial deploy
- **Excluded by default**: `/aws/lambda/logsentry*`, `/aws/cloudtrail*`, `/aws/rds*` (configurable)

---

## Step 1: Bootstrap Terraform Backend

These resources store Terraform's own state. Run **once** before first `terraform init`:

```bash
# Create S3 bucket for state
aws s3 mb s3://logsentry-terraform-state --region us-east-1
aws s3api put-bucket-versioning \
  --bucket logsentry-terraform-state \
  --versioning-configuration Status=Enabled

# Create DynamoDB table for state locking
aws dynamodb create-table \
  --table-name terraform-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

Wait ~10 seconds for the DynamoDB table to become active.

---

## Step 2: Configure Environment

Edit `terraform/terraform.tfvars.dev`:

```hcl
aws_region                 = "us-east-1"
environment                = "dev"
alert_email                = "your-team@company.com"  # Optional: receive email alerts
log_group_exclude_prefixes = "/aws/lambda/logsentry,/aws/cloudtrail,/aws/rds"
findings_ttl_days          = 90    # Auto-expire resolved findings
alert_rate_limit           = 10    # Max alerts per Lambda invocation
```

---

## Step 3: Deploy Everything

```bash
cd terraform
terraform init
terraform apply -var-file=terraform.tfvars.dev -auto-approve
```

This creates all resources in one command:
- Kinesis stream (log buffer)
- Lambda scanner (zip deploy, no Docker needed)
- Auto-subscribe Lambda + EventBridge rules
- DynamoDB table (findings with TTL + severity GSI)
- SNS topic (alerts, rate-limited)
- SQS dead-letter queue
- CloudWatch alarms (error rate, critical findings)
- IAM roles (least-privilege)
- Subscription filters on all existing log groups

---

## Step 4: Verify It Works

```bash
# Create a test log group
aws logs create-log-group --log-group-name /app/test-logsentry
aws logs create-log-stream --log-group-name /app/test-logsentry --log-stream-name test-1

# Trigger auto-subscribe to pick it up
aws lambda invoke --function-name logsentry-auto-subscribe-dev \
  --payload '{"action":"scan_all","source":"scheduled"}' /tmp/out.json
cat /tmp/out.json

# Send a test log with a fake secret
aws logs put-log-events \
  --log-group-name /app/test-logsentry \
  --log-stream-name test-1 \
  --log-events "timestamp=$(date +%s)000,message=ERROR: password=TestSecret123! leaked"

# Wait 30 seconds for pipeline to process
sleep 30

# Check findings
aws dynamodb scan --table-name logsentry-findings-dev \
  --query 'Items[*].{severity:severity.S,description:description.S,service:log_group.S}' \
  --output table

# Clean up test
aws logs delete-log-group --log-group-name /app/test-logsentry
```

---

## Step 5: Run the Dashboard

```bash
# Install Flask
pip install flask boto3

# Demo mode (sample data, no AWS needed)
make dashboard

# Live mode (reads from DynamoDB)
make dashboard-live
```

Open http://localhost:8080

Dashboard features:
- Real-time findings list with severity filtering
- Stats overview (total, critical, high, medium, open, resolved)
- Live scanner (paste any log line to test detection)
- Resolve button (mark findings as remediated)
- Pattern breakdown and affected services charts

---

## Step 6: Deploy via CI/CD

Set these in your GitHub repo (Settings → Secrets and variables → Actions):

**Variables:**
- `AWS_ENABLED` = `true`

**Secrets:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

Push to `dev` or `main` branch. The pipeline will:
1. Run tests (pytest)
2. Security scan (Trivy)
3. Deploy Lambda (zip upload)

---

## How Auto-Subscribe Works

| Trigger | Latency | Requirement |
|---|---|---|
| EventBridge (new log group) | Instant | CloudTrail enabled |
| Scheduled scan | ≤ 5 minutes | None |
| First deploy | Immediate | `terraform apply` |

### CloudTrail (Optional but Recommended)

For instant auto-subscribe when new log groups are created:

```bash
aws cloudtrail create-trail \
  --name logsentry-trail \
  --s3-bucket-name logsentry-terraform-state \
  --is-multi-region-trail
aws cloudtrail start-logging --name logsentry-trail
```

Without CloudTrail, the scheduled scan (every 5 min) handles new log groups.

---

## Updating the Scanner

After modifying `scanner/handler.py`:

```bash
# Local: deploy directly
make deploy

# CI: push to dev/main branch (auto-deploys via GitHub Actions)
git push origin dev
```

---

## Configuration Reference

| Variable | Description | Default |
|---|---|---|
| `aws_region` | AWS region | `us-east-1` |
| `environment` | `dev` or `prod` | `dev` |
| `alert_email` | Email for SNS alerts (empty = disabled) | `""` |
| `log_group_exclude_prefixes` | Comma-separated prefixes to skip | `/aws/lambda/logsentry,/aws/cloudtrail,/aws/rds` |
| `findings_ttl_days` | Days to keep resolved findings before auto-delete | `90` |
| `alert_rate_limit` | Max SNS alerts per Lambda invocation | `10` |

---

## Teardown

```bash
cd terraform
terraform destroy -var-file=terraform.tfvars.dev -auto-approve
```

Note: S3 state bucket and DynamoDB lock table have `prevent_destroy`. Remove those lifecycle rules from `main.tf` first if you want full teardown.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| Auto-subscribe not firing | Ensure CloudTrail is enabled, or wait for 5-min scheduled scan |
| Subscription filter fails | Log group may already have 2 filters (AWS max) |
| Tests fail in CI | `handler.py` uses lazy boto3 init — works without AWS creds |
| Dashboard shows no data | Set `LOGSENTRY_MODE=live` and correct `FINDINGS_TABLE` |
| Lambda timeout | Increase `timeout` in main.tf (default: 60s) |
| Alert storms | Reduce `alert_rate_limit` variable |
