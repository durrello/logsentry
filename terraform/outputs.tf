output "kinesis_stream_arn" {
  value = aws_kinesis_stream.log_stream.arn
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.scanner.function_name
}

output "ecr_repository_url" {
  value = aws_ecr_repository.scanner.repository_url
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}
