# EC2 Tag Compliance Monitor

Config-free AWS tag compliance scanner with escalation. Scans EC2 instances for missing required tags, identifies the resource creator via CloudTrail, and sends email notifications via SNS to Team DL or FinOps DL (no direct creator emails). Creator/owner identity is included in the email so the team can reach out to that person. Day 0 / Day 3 / Day 5 escalation. Deployed via **Terraform**.

## What It Does

- **Scans** EC2 instances (single region or all regions) for missing required tags
- **Resolves recipient** via OwnerEmail tag or CloudTrail creator → Team DL or FinOps DL. When the creator/owner is a person (OwnerEmail, Human IAM, SSO), the email to the team DL includes a note: **please reach out to [X] and add the following tags: [Y]**.
- **Sends notifications** via SNS with escalation:
  - **Day 0**: Initial notification to Team DL or FinOps DL
  - **Day 3**: Reminder
  - **Day 5**: Escalate to FinOps/Team Lead
- **Auto-closes** when tags are fixed
- **Runs on schedule** via EventBridge (daily by default)

## Prerequisites

| Prerequisite | Notes |
|--------------|-------|
| **Terraform** | >= 1.0 |
| **AWS credentials** | Configured for the target account |
| **SNS** | FinOps DL and Team DL must confirm their email subscriptions (AWS sends confirmation emails). |
| **CloudTrail** | Enabled and logging `RunInstances` so creator resolution works. |

## Who Gets Notified

| Variable | Purpose |
|----------|---------|
| `fallback_finops_dl` | **To** — unknown creator / no trail / human with no email mapping |
| `terraform_team_dl` | **To** — Terraform/CI-CD roles and creator cases (team is asked to reach out to the person and add tags) |
| `platform_app_dl` | **To** — CI/CD role (optional; empty => FinOps DL) |

Recipient is chosen per instance: OwnerEmail tag or CloudTrail creator (Human, SSO, Terraform, CI/CD) → Team DL or FinOps DL. Creator identity is included in the email body so the team can contact that person; no direct emails to creators.

## Deploy with Terraform

### 1. Configure variables

Create `terraform/terraform.tfvars`:

```hcl
fallback_finops_dl  = "finops@yourcompany.com"
terraform_team_dl   = "cloud-team@yourcompany.com"

# Optional
platform_app_dl   = ""
aws_region        = "us-east-1"
region_scope      = ""                    # "" = current region; "all" = all regions
schedule_expression = "rate(1 day)"
sns_topic_name    = "TagComplianceNotifications"
```

After deploy, FinOps DL and Team DL will receive SNS subscription confirmation emails from AWS; they must confirm to receive notifications.

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

Ensure CloudTrail is set up in each target account. SNS subscriptions (FinOps DL, Team DL) must be confirmed via the emails AWS sends.

## Test

```bash
aws lambda invoke --function-name TagComplianceScanner --payload '{}' out.json
cat out.json
```

## Terraform variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `fallback_finops_dl` | Yes | — | FinOps DL email (SNS subscription) |
| `terraform_team_dl` | Yes | — | Team DL for Terraform/CI-CD and creator cases (SNS subscription) |
| `platform_app_dl` | No | `""` | Platform/App DL |
| `sns_topic_name` | No | `TagComplianceNotifications` | SNS topic name |
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
├── main.py           # Lambda handler (scanner)
├── README.md
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
