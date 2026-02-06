terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Lambda deployment package (main.py from parent directory)
data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../main.py"
  output_path = "${path.module}/lambda.zip"
}

# DynamoDB state table (pk/sk, TTL for closed cases)
resource "aws_dynamodb_table" "state" {
  name         = var.state_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "closedAtTTL"
    enabled        = true
  }
}

# IAM role for Lambda
resource "aws_iam_role" "lambda" {
  name = "${var.function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy: EC2, CloudTrail, DynamoDB, SES
resource "aws_iam_role_policy" "lambda" {
  name   = "${var.function_name}-policy"
  role   = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeRegions", "ec2:DescribeInstances"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchGetItem",
          "dynamodb:Query"
        ]
        Resource = [aws_dynamodb_table.state.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["ses:SendEmail", "ses:SendRawEmail"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Lambda function
resource "aws_lambda_function" "scanner" {
  filename         = data.archive_file.lambda.output_path
  function_name    = var.function_name
  role             = aws_iam_role.lambda.arn
  handler          = "main.lambda_handler"
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 256
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      STATE_TABLE             = aws_dynamodb_table.state.name
      SES_FROM_ADDRESS        = var.ses_from_address
      FINOPS_DL               = var.fallback_finops_dl
      TEAM_DL                 = var.terraform_team_dl
      PLATFORM_APP_DL         = var.platform_app_dl != "" ? var.platform_app_dl : var.fallback_finops_dl
      REQUIRED_TAGS           = var.required_tags
      CLOUDTRAIL_LOOKBACK_DAYS = var.cloudtrail_lookback_days
      EMAIL_DOMAIN            = var.email_domain
      USER_MAP_TABLE          = var.user_map_table
      REGION_SCOPE            = var.region_scope
    }
  }

  depends_on = [aws_iam_role_policy.lambda]
}

# EventBridge rule (daily schedule)
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.function_name}-schedule"
  description         = "Daily trigger for tag compliance scan"
  schedule_expression = var.schedule_expression
}

# EventBridge target: invoke Lambda
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "TagComplianceLambda"
  arn       = aws_lambda_function.scanner.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
