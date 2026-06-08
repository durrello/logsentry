terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "logsentry-terraform-state"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "logsentry"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ─── Kinesis Stream ──────────────────────────────────────────────────────────
resource "aws_kinesis_stream" "log_stream" {
  name             = "logsentry-log-stream-${var.environment}"
  shard_count      = var.environment == "prod" ? 2 : 1
  retention_period = 24

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }
}

# ─── DynamoDB Table ──────────────────────────────────────────────────────────
resource "aws_dynamodb_table" "findings" {
  name         = "logsentry-findings-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  attribute {
    name = "detected_at"
    type = "S"
  }

  global_secondary_index {
    name            = "severity-index"
    hash_key        = "severity"
    range_key       = "detected_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}

# ─── SNS Topic ──────────────────────────────────────────────────────────────
resource "aws_sns_topic" "alerts" {
  name = "logsentry-alerts-${var.environment}"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ─── Lambda Function ─────────────────────────────────────────────────────────
resource "aws_lambda_function" "scanner" {
  function_name = "logsentry-scanner-${var.environment}"
  role          = aws_iam_role.lambda_role.arn
  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.scanner.repository_url}:latest"
  timeout       = 60
  memory_size   = 256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      ENVIRONMENT    = var.environment
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}

# ─── Lambda Event Source (Kinesis) ───────────────────────────────────────────
resource "aws_lambda_event_source_mapping" "kinesis_trigger" {
  event_source_arn  = aws_kinesis_stream.log_stream.arn
  function_name     = aws_lambda_function.scanner.arn
  starting_position = "LATEST"
  batch_size        = 100

  maximum_retry_attempts         = 3
  bisect_batch_on_function_error = true
}

# ─── Dead Letter Queue ───────────────────────────────────────────────────────
resource "aws_sqs_queue" "dlq" {
  name                      = "logsentry-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
}

# ─── ECR Repository ─────────────────────────────────────────────────────────
resource "aws_ecr_repository" "scanner" {
  name                 = "logsentry-scanner-${var.environment}"
  image_tag_mutability = "MUTABLE"
  force_delete         = var.environment == "dev"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ─── IAM Role for Lambda ────────────────────────────────────────────────────
resource "aws_iam_role" "lambda_role" {
  name = "logsentry-lambda-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "logsentry-lambda-policy-${var.environment}"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:GetRecords",
          "kinesis:GetShardIterator",
          "kinesis:DescribeStream",
          "kinesis:ListStreams",
          "kinesis:ListShards",
        ]
        Resource = aws_kinesis_stream.log_stream.arn
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
        ]
        Resource = [
          aws_dynamodb_table.findings.arn,
          "${aws_dynamodb_table.findings.arn}/index/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
        ]
        Resource = aws_sqs_queue.dlq.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
    ]
  })
}

# ─── CloudWatch Subscription Filter (example) ───────────────────────────────
resource "aws_iam_role" "cloudwatch_to_kinesis" {
  name = "logsentry-cw-to-kinesis-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "cloudwatch_to_kinesis" {
  name = "logsentry-cw-kinesis-policy-${var.environment}"
  role = aws_iam_role.cloudwatch_to_kinesis.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kinesis:PutRecord", "kinesis:PutRecords"]
      Resource = aws_kinesis_stream.log_stream.arn
    }]
  })
}

# ─── Auto-Subscribe: Subscribe ALL log groups automatically ──────────────────
# This Lambda is triggered by EventBridge whenever a new CloudWatch Log Group
# is created. It automatically adds a subscription filter so every log group
# is scanned by LogSentry without manual intervention.

resource "aws_lambda_function" "auto_subscribe" {
  function_name = "logsentry-auto-subscribe-${var.environment}"
  role          = aws_iam_role.auto_subscribe_role.arn
  runtime       = "python3.11"
  handler       = "index.handler"
  timeout       = 30
  memory_size   = 128

  filename         = data.archive_file.auto_subscribe.output_path
  source_code_hash = data.archive_file.auto_subscribe.output_base64sha256

  environment {
    variables = {
      KINESIS_STREAM_ARN = aws_kinesis_stream.log_stream.arn
      CW_ROLE_ARN        = aws_iam_role.cloudwatch_to_kinesis.arn
      EXCLUDE_PREFIXES   = var.log_group_exclude_prefixes
    }
  }
}

data "archive_file" "auto_subscribe" {
  type        = "zip"
  output_path = "${path.module}/auto_subscribe.zip"

  source {
    content = <<-PYTHON
import os
import json
import boto3

logs = boto3.client('logs')
KINESIS_STREAM_ARN = os.environ['KINESIS_STREAM_ARN']
CW_ROLE_ARN = os.environ['CW_ROLE_ARN']
EXCLUDE_PREFIXES = [p.strip() for p in os.environ.get('EXCLUDE_PREFIXES', '').split(',') if p.strip()]

def should_exclude(log_group_name):
    """Check if log group should be excluded from scanning."""
    for prefix in EXCLUDE_PREFIXES:
        if log_group_name.startswith(prefix):
            return True
    return False

def subscribe_log_group(log_group_name):
    """Add subscription filter to a log group."""
    if should_exclude(log_group_name):
        return 'excluded'
    try:
        # Check if already subscribed
        existing = logs.describe_subscription_filters(logGroupName=log_group_name)
        filters = existing.get('subscriptionFilters', [])
        if any(f['filterName'].startswith('logsentry') for f in filters):
            return 'already_subscribed'
        if len(filters) >= 2:
            return 'max_filters'
        logs.put_subscription_filter(
            logGroupName=log_group_name,
            filterName='logsentry-auto',
            filterPattern='',
            destinationArn=KINESIS_STREAM_ARN,
            roleArn=CW_ROLE_ARN,
        )
        print(f"SUBSCRIBED: {log_group_name}")
        return 'subscribed'
    except Exception as e:
        print(f"ERROR: {log_group_name}: {e}")
        return 'error'

def scan_all_log_groups():
    """Scan all existing log groups and subscribe any that are missing."""
    paginator = logs.get_paginator('describe_log_groups')
    results = {'subscribed': 0, 'skipped': 0}
    for page in paginator.paginate():
        for lg in page['logGroups']:
            result = subscribe_log_group(lg['logGroupName'])
            if result == 'subscribed':
                results['subscribed'] += 1
            else:
                results['skipped'] += 1
    print(f"Scan complete: {results}")
    return results

def handler(event, context):
    """Handle both EventBridge (new log group) and scheduled (scan all) triggers."""
    # Scheduled invocation: scan all log groups
    if event.get('action') == 'scan_all' or event.get('source') == 'scheduled':
        results = scan_all_log_groups()
        return {'statusCode': 200, 'body': json.dumps(results)}

    # EventBridge: new log group created
    detail = event.get('detail', {})
    request_params = detail.get('requestParameters', {})
    log_group_name = request_params.get('logGroupName', '')

    if not log_group_name:
        print(f"No logGroupName in event: {json.dumps(event)}")
        return {'statusCode': 400, 'body': 'No log group name found'}

    result = subscribe_log_group(log_group_name)
    return {'statusCode': 200, 'body': f'{result}: {log_group_name}'}
PYTHON
    filename = "index.py"
  }
}

# IAM role for auto-subscribe Lambda
resource "aws_iam_role" "auto_subscribe_role" {
  name = "logsentry-auto-subscribe-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "auto_subscribe_policy" {
  name = "logsentry-auto-subscribe-policy-${var.environment}"
  role = aws_iam_role.auto_subscribe_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:PutSubscriptionFilter",
          "logs:DescribeLogGroups",
          "logs:DescribeSubscriptionFilters",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole",
        ]
        Resource = aws_iam_role.cloudwatch_to_kinesis.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
    ]
  })
}

# EventBridge rule: fires on any new CloudWatch Log Group creation
# NOTE: Requires CloudTrail to be enabled. If not available, the scheduled
# rule below handles it by polling every 5 minutes.
resource "aws_cloudwatch_event_rule" "new_log_group" {
  name        = "logsentry-new-log-group-${var.environment}"
  description = "Triggers auto-subscribe when a new CloudWatch Log Group is created"

  event_pattern = jsonencode({
    source      = ["aws.logs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["logs.amazonaws.com"]
      eventName   = ["CreateLogGroup"]
    }
  })
}

resource "aws_cloudwatch_event_target" "auto_subscribe" {
  rule = aws_cloudwatch_event_rule.new_log_group.name
  arn  = aws_lambda_function.auto_subscribe.arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_subscribe.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.new_log_group.arn
}

# ─── Subscribe existing log groups (one-time via local-exec) ─────────────────
# On first deploy, subscribe all existing log groups that match the include pattern.
resource "null_resource" "subscribe_existing_log_groups" {
  depends_on = [
    aws_iam_role_policy.cloudwatch_to_kinesis,
    aws_kinesis_stream.log_stream,
  ]

  provisioner "local-exec" {
    command = <<-EOT
      python3 ${path.module}/scripts/subscribe_existing.py \
        --stream-arn ${aws_kinesis_stream.log_stream.arn} \
        --role-arn ${aws_iam_role.cloudwatch_to_kinesis.arn} \
        --exclude "${var.log_group_exclude_prefixes}" \
        --region ${var.aws_region}
    EOT
  }

  triggers = {
    # Re-run if stream ARN changes
    stream_arn = aws_kinesis_stream.log_stream.arn
  }
}

# ─── Scheduled scan: catch unsubscribed log groups every 5 minutes ───────────
# This ensures log groups are subscribed even without CloudTrail.
# The auto-subscribe Lambda handles both event-driven AND scheduled invocations.

resource "aws_cloudwatch_event_rule" "scheduled_scan" {
  name                = "logsentry-scheduled-scan-${var.environment}"
  description         = "Periodically scan for unsubscribed log groups"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "scheduled_scan" {
  rule  = aws_cloudwatch_event_rule.scheduled_scan.name
  arn   = aws_lambda_function.auto_subscribe.arn
  input = jsonencode({ source = "scheduled", action = "scan_all" })
}

resource "aws_lambda_permission" "scheduled_invoke" {
  statement_id  = "AllowScheduledInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_subscribe.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_scan.arn
}

# ─── Demo Log Group (for testing) ───────────────────────────────────────────
resource "aws_cloudwatch_log_group" "demo_service" {
  name              = "/app/demo-service"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_subscription_filter" "demo_to_kinesis" {
  name            = "logsentry-scanner"
  log_group_name  = aws_cloudwatch_log_group.demo_service.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_stream.log_stream.arn
  role_arn        = aws_iam_role.cloudwatch_to_kinesis.arn
}

# ─── Bootstrap: Terraform State Backend ──────────────────────────────────────
# These resources are the S3 bucket and DynamoDB table that Terraform itself
# uses for remote state. They must exist before `terraform init`, so they are
# created once manually (or via a separate bootstrap script) and then imported.
# Included here for documentation and drift detection.

resource "aws_s3_bucket" "terraform_state" {
  bucket = "logsentry-terraform-state"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_dynamodb_table" "terraform_lock" {
  name         = "terraform-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  lifecycle {
    prevent_destroy = true
  }
}
