# Terraform: Tag Compliance Scanner

Deploys the EC2 tag compliance scanner Lambda with EventBridge schedule, DynamoDB state table, and IAM.

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured with credentials
- CloudTrail enabled and logging `RunInstances`

## Required Variables

| Variable | Description |
|----------|-------------|
| `fallback_finops_dl` | FinOps DL for unknown creator / no trail |
| `terraform_team_dl` | Team DL for Terraform/CI-CD and creator cases |

## Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | `us-east-1` | AWS region |
| `function_name` | `TagComplianceScanner` | Lambda name |
| `state_table_name` | `TagComplianceState` | DynamoDB table name |
| `platform_app_dl` | `""` | Platform/App DL (empty => uses fallback_finops_dl) |
| `required_tags` | (12 tags) | Comma-separated required tag keys |
| `cloudtrail_lookback_days` | `30` | Days to look back for creator |
| `email_domain` | `""` | Domain for user emails (username@domain) |
| `user_map_table` | `""` | DynamoDB table for IAM username → email |
| `region_scope` | `""` | `all` for all regions; empty for current only |
| `schedule_expression` | `rate(1 day)` | EventBridge schedule |

## Deploy

1. Initialize Terraform:
   ```bash
   terraform init
   ```

2. Plan (provide required variables):
   ```bash
   terraform plan \
     -var="fallback_finops_dl=finops@example.com" \
     -var="terraform_team_dl=team@example.com"
   ```

3. Apply:
   ```bash
   terraform apply \
     -var="fallback_finops_dl=finops@example.com" \
     -var="terraform_team_dl=team@example.com"
   ```

Alternatively, create `terraform.tfvars`:

```hcl
fallback_finops_dl   = "finops@example.com"
terraform_team_dl    = "team@example.com"
```

Then run:

```bash
terraform init
terraform plan
terraform apply
```

## Lambda Package

Lambda code is packaged automatically via Terraform `archive_file` (from `../main.py`). No manual zip step required. Run `terraform apply` to deploy updated code.

## Test

```bash
aws lambda invoke --function-name TagComplianceScanner --payload '{}' out.json && cat out.json
```
