output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.scanner.function_name
}

output "lambda_function_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.scanner.arn
}

output "state_table_name" {
  description = "DynamoDB state table name"
  value       = aws_dynamodb_table.state.name
}

output "eventbridge_rule_arn" {
  description = "EventBridge schedule rule ARN"
  value       = aws_cloudwatch_event_rule.schedule.arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN for compliance notifications"
  value       = aws_sns_topic.compliance.arn
}
