output "kinesis_stream_arn" {
  description = "ARN of the Kinesis stream (for manual log group subscriptions)"
  value       = aws_kinesis_stream.log_stream.arn
}

output "dynamodb_table_name" {
  description = "DynamoDB table storing findings"
  value       = aws_dynamodb_table.findings.name
}

output "sns_topic_arn" {
  description = "SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  description = "Scanner Lambda function name"
  value       = aws_lambda_function.scanner.function_name
}

output "dlq_url" {
  description = "Dead letter queue URL"
  value       = aws_sqs_queue.dlq.url
}

output "cw_to_kinesis_role_arn" {
  description = "IAM role ARN for CloudWatch to Kinesis (use when manually subscribing log groups)"
  value       = aws_iam_role.cloudwatch_to_kinesis.arn
}
