variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment (dev or prod)"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Must be dev or prod."
  }
}

variable "alert_email" {
  description = "Email for SNS alerts (leave empty to disable)"
  type        = string
  default     = ""
}

variable "log_group_exclude_prefixes" {
  description = "Comma-separated prefixes of log groups to exclude from scanning"
  type        = string
  default     = "/aws/lambda/logsentry,/aws/cloudtrail,/aws/rds"
}

variable "findings_ttl_days" {
  description = "Days to keep resolved findings before auto-expiring (0 = never expire)"
  type        = number
  default     = 90
}

variable "alert_rate_limit" {
  description = "Max SNS alerts per invocation (prevents alert storms)"
  type        = number
  default     = 10
}
