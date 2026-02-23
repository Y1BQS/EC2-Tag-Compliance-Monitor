resource "aws_iam_policy" "quicksight_tag_compliance" {
  name        = "${var.function_name}-quicksight-tag-compliance"
  description = "Allow QuickSight to read TagComplianceState for EC2 tag compliance dashboard"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "dynamodb:DescribeTable",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.state.arn
        ]
      }
    ]
  })
}

