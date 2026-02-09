variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "function_name" {
  description = "Lambda function name"
  type        = string
  default     = "TagComplianceScanner"
}

variable "state_table_name" {
  description = "DynamoDB state table name"
  type        = string
  default     = "TagComplianceState"
}

variable "ses_from_address" {
  description = "SES verified From address (e.g. your test sender)"
  type        = string
}

variable "fallback_finops_dl" {
  description = "FinOps DL email for unknown creator / no trail"
  type        = string
}

variable "terraform_team_dl" {
  description = "Team DL email for Terraform/CI-CD roles"
  type        = string
}

variable "platform_app_dl" {
  description = "(Optional) Platform/App DL for CI/CD role; defaults to fallback_finops_dl if empty"
  type        = string
  default     = ""
}

variable "required_tags" {
  description = "Comma-separated required tag keys"
  type        = string
  default     = "app-name,created-by,app-owner,infra-owner,department,environment,schedule,compliance,data-classification,project-id,servicenow-asset-tracking,expense-type"
}

variable "cloudtrail_lookback_days" {
  description = "Days to look back in CloudTrail for creator"
  type        = string
  default     = "30"
}

variable "email_domain" {
  description = "(Optional) Domain to build user emails, e.g. yourcompany.com"
  type        = string
  default     = ""
}

variable "user_map_table" {
  description = "(Optional) DynamoDB table name for IAM username to email mapping"
  type        = string
  default     = ""
}

variable "region_scope" {
  description = "Leave empty for current region only; set to 'all' for all regions"
  type        = string
  default     = ""
}

variable "schedule_expression" {
  description = "EventBridge schedule (e.g. rate(1 day) or cron(0 13 * * ? *) for 09:00 EDT / 13:00 UTC daily)"
  type        = string
  default     = "cron(0 13 * * ? *)"
}
