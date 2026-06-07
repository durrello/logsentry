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
