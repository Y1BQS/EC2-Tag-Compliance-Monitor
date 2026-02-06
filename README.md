# EC2 Tag Compliance Monitor

Config-free AWS tag compliance scanner with escalation. Scans EC2 instances for missing required tags, identifies the resource creator via CloudTrail, and sends email alerts with a Day 0 / Day 3 / Day 5 escalation flow. Deployed via **Terraform**.

## What It Does

- **Scans** EC2 instances (single region or all regions) for missing required tags
- **Resolves recipient** via OwnerEmail tag or CloudTrail creator (Human, Terraform role, CI/CD role, or FinOps DL)
- **Sends emails** via SES with escalation:
  - **Day 0**: Initial notification to creator
  - **Day 3**: Reminder
  - **Day 5**: Escalate to creator + FinOps/Team Lead
- **Auto-closes** when tags are fixed
- **Runs on schedule** via EventBridge (daily by default)

## Prerequisites

| Prerequisite | Notes |
|--------------|-------|
| **Terraform** | >= 1.0 |
| **AWS credentials** | Configured for the target account |
| **SES** | Verify the **From** address. In sandbox, also verify every **To** address (FinOps DL, Team DL, creator emails). |
| **CloudTrail** | Enabled and logging `RunInstances` so creator resolution works. |

## Who Gets Emailed

| Variable | Purpose |
|----------|---------|
| `ses_from_address` | **From** — verified sender in SES |
| `fallback_finops_dl` | **To** — unknown creator / no trail / human with no email mapping |
| `terraform_team_dl` | **To** — Terraform/CI-CD roles |
| `platform_app_dl` | **To** — CI/CD role (optional; empty => FinOps DL) |

Recipient is chosen per instance: OwnerEmail tag → CloudTrail creator (Human, SSO, Terraform, CI/CD) → FinOps DL.

## Deploy with Terraform

### 1. Configure variables

Create `terraform/terraform.tfvars`:

```hcl
ses_from_address    = "compliance@yourcompany.com"
fallback_finops_dl  = "finops@yourcompany.com"
terraform_team_dl   = "cloud-team@yourcompany.com"

# Optional
platform_app_dl   = ""
aws_region        = "us-east-1"
region_scope      = ""                    # "" = current region; "all" = all regions
schedule_expression = "rate(1 day)"
```

### 2. Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### 3. Deploy to another AWS account

Use an AWS profile or assume role:

```bash
AWS_PROFILE=other-account terraform init
AWS_PROFILE=other-account terraform apply -var-file=terraform.tfvars
```

Ensure SES and CloudTrail are set up in each target account.

## Test

```bash
aws lambda invoke --function-name TagComplianceScanner --payload '{}' out.json
cat out.json
```

## Terraform variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ses_from_address` | Yes | — | SES verified From address |
| `fallback_finops_dl` | Yes | — | FinOps DL |
| `terraform_team_dl` | Yes | — | Team DL for Terraform/CI-CD |
| `platform_app_dl` | No | `""` | Platform/App DL |
| `aws_region` | No | `us-east-1` | AWS region |
| `function_name` | No | `TagComplianceScanner` | Lambda name |
| `state_table_name` | No | `TagComplianceState` | DynamoDB table |
| `required_tags` | No | (12 tags) | Comma-separated required tag keys |
| `cloudtrail_lookback_days` | No | `30` | Days to look back for creator |
| `email_domain` | No | `""` | Domain for username@domain |
| `user_map_table` | No | `""` | DynamoDB table for username → email |
| `region_scope` | No | `""` | `all` for all regions |
| `schedule_expression` | No | `rate(1 day)` | EventBridge schedule |

## Project structure

```
├── main.py           # Lambda handler
├── README.md
├── template.yaml     # Legacy SAM (reference)
└── terraform/
    ├── main.tf
    ├── variables.tf
    ├── outputs.tf
    └── README.md
```

## Updating the Lambda

Edit `main.py` and run:

```bash
cd terraform
terraform apply
```
