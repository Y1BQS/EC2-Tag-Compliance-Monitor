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
| `analytics_bucket_name` | No | (generated) | S3 bucket for run metrics |
| `run_metrics_prefix` | No | `runs/` | S3 prefix for run metrics |
| `analytics_retention_days` | No | `90` | Delete analytics objects (runs/, missing-tags/) after N days; use `0` to disable |

## Optional QuickSight dashboard setup (manual, S3 only)

After Terraform is applied, the Lambda writes two S3 streams for QuickSight:

- **Run metrics**: `s3://<analytics-bucket>/runs/YYYY/MM/DD/run-YYYYMMDD-HHMMSS.json` (one wide JSON object per run).
- **Missing-tags summary**: `s3://<analytics-bucket>/missing-tags/YYYY/MM/DD/missing-tags-YYYYMMDD-HHMMSS.csv` (CSV with header: `run_timestamp`, `account_id`, `region_scope`, `total_scanned`, `total_noncompliant`, `total_notified`, `tag_name`, `instance_count`).

### Prerequisites

- Terraform applied (analytics S3 bucket exists).
- Lambda has run at least once so `runs/` and (if any non-compliant instances) `missing-tags/` have data.

### 1. IAM for QuickSight (S3)

Attach a policy that allows read on both prefixes:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::<analytics-bucket>"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": [
        "arn:aws:s3:::<analytics-bucket>/runs/*",
        "arn:aws:s3:::<analytics-bucket>/missing-tags/*"
      ]
    }
  ]
}
```

Replace `<analytics-bucket>` with Terraform output `analytics_bucket_name`.

### 2. Run metrics dataset and visuals

The Lambda writes both:

- **Historical per-run metrics** (JSON): `s3://<analytics-bucket>/runs/YYYY/MM/DD/run-YYYYMMDD-HHMMSS.json`
- **Latest snapshot (overwritten each run, CSV)**: `s3://<analytics-bucket>/summary/summary.csv` (columns: `category`, `count`, with two rows: `Compliant` and `Non-Compliant`)

1. **New dataset** → S3 → point at `runs/` (manifest or bucket/prefix), format **JSON**.
2. Fields: `run_timestamp`, `account_id`, `region_scope`, `total_scanned`, `total_compliant`, `total_noncompliant`, `total_notified`.
3. **Visuals**:
   - For **history/trends**, build visuals from the `runs/` dataset.
   - For a **current snapshot only**, create a second dataset pointing at `summary/` (format **CSV**, fields: `category`, `count`) and build your pie chart/KPIs from that dataset.

### 3. Missing-tags dataset and bar chart

The Lambda writes a single CSV under the `missing-tags/` prefix and overwrites it each run:

- `s3://<analytics-bucket>/missing-tags/missing-tags.csv`

1. **New dataset** → S3 → point at `missing-tags/` (files are `.csv`).
2. Set file format to **CSV**. Fields: `category`, `count` (one row per tag; `category` = tag name, `count` = number of instances missing that tag).
3. **Bar chart: instances missing per tag**
   - X-axis: `category`
   - Value: `count` (sum). You can filter or limit to focus on the most common missing tags.

## Project structure

```
├── main.py           # Lambda handler (scanner)
├── README.md
└── terraform/
    ├── main.tf       # Lambda, DynamoDB, SNS, EventBridge
    ├── analytics.tf  # S3 analytics bucket for QuickSight (S3 data source)
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
