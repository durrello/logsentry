# LogSentry — First-Time Setup Guide

This guide covers everything needed to deploy LogSentry from scratch. After setup, **all CloudWatch log groups are automatically monitored** — no manual steps needed for new services.

---

## Prerequisites

| Tool | Version | Check |
|---|---|---|
| AWS CLI | v2+ | `aws --version` |
| Terraform | >= 1.5 | `terraform --version` |
| Python | 3.11+ | `python3 --version` |
| Docker | Desktop or Engine | `docker --version` |

AWS CLI must be configured with credentials that have admin access:
```bash
aws sts get-caller-identity
```

---

## How It Works (After Setup)

```
Any Service → CloudWatch Logs → [Auto-Subscribe] → Kinesis → Lambda Scanner → DynamoDB + SNS
```

- **New log groups** are auto-subscribed via EventBridge (triggered on `CreateLogGroup`)
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

Edit `terraform/terraform.tfvars.dev` (or create `terraform.tfvars.prod` for production):

```hcl
aws_region  = "us-east-1"
environment = "dev"
alert_email = "your-team@company.com"  # Optional: receive email alerts

# Log groups matching these prefixes are NOT scanned (comma-separated)
# Default: "/aws/lambda/logsentry,/aws/cloudtrail,/aws/rds"
log_group_exclude_prefixes = "/aws/lambda/logsentry,/aws/cloudtrail,/aws/rds"
```

---

## Step 3: Build & Push Scanner Image

```bash
# Login to ECR (run terraform first to create the repo, or create manually)
cd terraform
terraform init
terraform apply -var-file=terraform.tfvars.dev -target=aws_ecr_repository.scanner -auto-approve

# Get the ECR URI from output
ECR_URI=$(terraform output -raw ecr_repository_url)

# Build for Lambda (must be linux/amd64, no attestations)
cd ../scanner
docker build --platform linux/amd64 --provenance=false -t $ECR_URI:latest .

# Push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $ECR_URI
docker push $ECR_URI:latest
```

---

## Step 4: Deploy Everything

```bash
cd terraform
terraform apply -var-file=terraform.tfvars.dev -auto-approve
```

This creates:
- Kinesis stream (log buffer)
- Lambda scanner (secret detection)
- DynamoDB table (findings storage)
- SNS topic (alerts)
- SQS dead-letter queue (failed events)
- ECR repository (container images)
- IAM roles (least-privilege)
- EventBridge rule + auto-subscribe Lambda (monitors new log groups)
- Subscription filters on all existing log groups

---

## Step 5: Verify It Works

```bash
# Create a test log group (auto-subscribe will pick it up if CloudTrail is enabled)
aws logs create-log-group --log-group-name /app/test-logsentry
aws logs create-log-stream --log-group-name /app/test-logsentry --log-stream-name test-1

# Manually subscribe it (or wait for EventBridge if CloudTrail is active)
aws logs put-subscription-filter \
  --log-group-name /app/test-logsentry \
  --filter-name logsentry-auto \
  --filter-pattern "" \
  --destination-arn $(cd terraform && terraform output -raw kinesis_stream_arn) \
  --role-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/logsentry-cw-to-kinesis-dev

# Send a test log with a fake secret
aws logs put-log-events \
  --log-group-name /app/test-logsentry \
  --log-stream-name test-1 \
  --log-events "timestamp=$(date +%s000),message=ERROR: password=TestSecret123! leaked"

# Wait 30 seconds, then check findings
sleep 30
aws dynamodb scan --table-name logsentry-findings-dev --query 'Items[*].{severity:severity.S,description:description.S,service:log_group.S}' --output table
```

---

## Step 6: Run the Dashboard

```bash
# Demo mode (sample data, no AWS needed)
make dashboard

# Live mode (reads from DynamoDB)
make dashboard-live
```

Open http://localhost:8080

---

## How Auto-Subscribe Works

| Trigger | What Happens |
|---|---|
| **New log group created** | EventBridge detects `CreateLogGroup` API call → triggers `logsentry-auto-subscribe` Lambda → adds subscription filter |
| **First deploy** | `subscribe_existing.py` runs via Terraform `local-exec` → subscribes all existing log groups |
| **Excluded log groups** | Anything matching `log_group_exclude_prefixes` is skipped |

### Important: CloudTrail Requirement

The auto-subscribe EventBridge rule listens for CloudTrail events. If CloudTrail is not enabled in your account, the auto-subscribe won't fire for new log groups. In that case:

**Option A (recommended):** Enable CloudTrail:
```bash
aws cloudtrail create-trail --name logsentry-trail --s3-bucket-name logsentry-terraform-state --is-multi-region-trail
aws cloudtrail start-logging --name logsentry-trail
```

**Option B:** Manually subscribe new log groups:
```bash
aws logs put-subscription-filter \
  --log-group-name /your/new/service \
  --filter-name logsentry-auto \
  --filter-pattern "" \
  --destination-arn <KINESIS_STREAM_ARN> \
  --role-arn <CW_TO_KINESIS_ROLE_ARN>
```

---

## Configuration Reference

| Variable | Description | Default |
|---|---|---|
| `aws_region` | AWS region | `us-east-1` |
| `environment` | `dev` or `prod` | `dev` |
| `alert_email` | Email for SNS alerts (leave empty to disable) | `""` |
| `log_group_exclude_prefixes` | Comma-separated prefixes to skip | `/aws/lambda/logsentry,/aws/cloudtrail,/aws/rds` |

---

## Teardown

To destroy all resources:
```bash
cd terraform
terraform destroy -var-file=terraform.tfvars.dev -auto-approve
```

Note: The S3 state bucket and DynamoDB lock table have `prevent_destroy` lifecycle rules. Remove those from `main.tf` first if you want to fully tear down.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| Lambda image not supported | Rebuild with `--platform linux/amd64 --provenance=false` |
| Auto-subscribe not firing | Ensure CloudTrail is enabled (EventBridge needs it) |
| Subscription filter fails | Check log group doesn't already have 2 filters (AWS max) |
| Tests fail in CI | `handler.py` uses lazy boto3 init — if tests import handler, they work without AWS creds |
| Dashboard shows no data | Set `LOGSENTRY_MODE=live` and `FINDINGS_TABLE=logsentry-findings-dev` |
