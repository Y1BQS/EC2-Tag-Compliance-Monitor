# --- Analytics S3 bucket for QuickSight (no Athena/Glue) ---

data "aws_caller_identity" "current" {}

locals {
  analytics_bucket = coalesce(
    var.analytics_bucket_name,
    lower(replace("${var.function_name}-analytics-${data.aws_caller_identity.current.account_id}", "_", "-"))
  )
}

# S3 bucket for run metrics (Lambda writes one JSON file per scan; QuickSight reads)
resource "aws_s3_bucket" "analytics" {
  bucket = local.analytics_bucket
}

resource "aws_s3_bucket_versioning" "analytics" {
  bucket = aws_s3_bucket.analytics.id

  versioning_configuration {
    status = "Disabled"
  }
}

# Optional: default SSE-S3 for all objects (in addition to explicit SSE in Lambda)
resource "aws_s3_bucket_server_side_encryption_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle: delete run metrics and missing-tags data after N days (keeps QuickSight history bounded)
resource "aws_s3_bucket_lifecycle_configuration" "analytics" {
  count  = var.analytics_retention_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.analytics.id

  rule {
    id     = "expire-runs"
    status = "Enabled"
    filter {
      prefix = "runs/"
    }
    expiration {
      days = var.analytics_retention_days
    }
  }
}

