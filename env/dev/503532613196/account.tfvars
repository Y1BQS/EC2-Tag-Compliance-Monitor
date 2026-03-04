################################################################################
# Sandbox Account Configuration for Tag Compliance Scanner
################################################################################

aws_account_id  = "503532613196"
aws_region      = "us-east-1"

# IAM role that GitHub Actions will assume via OIDC for this account
assume_role_arn = "arn:aws:iam::347116755583:role/github-terraform-aws"

# Remote Terraform state bucket for this account/environment
tf_state_bucket = "ns-terraform-state-503532613196"
tf_state_region = "us-east-1"

# Required variables for this Terraform stack
fallback_finops_dl = "khanhamza2293@gmail.com"
terraform_team_dl  = "hamza.khan@nscorp.com"

# Optional: override defaults if needed
# platform_app_dl      = ""
# required_tags        = "app-name,created-by,app-owner,infra-owner,department,environment,schedule,compliance,data-classification,project-id,servicenow-asset-tracking,expense-type"
# cloudtrail_lookback_days = "30"
# email_domain         = ""
# user_map_table       = ""
# region_scope         = ""
# analytics_bucket_name = ""
# run_metrics_prefix    = "runs/"
# analytics_retention_days = 90

tags = {
  app-name    = "tag-compliance-scanner"
  environment = "sandbox"
  ManagedBy   = "terraform"
}

