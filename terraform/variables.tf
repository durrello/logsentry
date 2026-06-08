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
  description = "Email for SNS alerts"
  type        = string
  default     = ""
}

variable "log_group_exclude_prefixes" {
  description = "Comma-separated prefixes of log groups to exclude from scanning (e.g. /aws/lambda/logsentry,/aws/rds)"
  type        = string
  default     = "/aws/lambda/logsentry,/aws/cloudtrail,/aws/rds"
}
