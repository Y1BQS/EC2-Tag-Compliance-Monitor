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

## Deploy with Terraform (locally)

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

### 3. Deploy to another AWS account (locally)

Use an AWS profile or assume role:

```bash
AWS_PROFILE=other-account terraform init
AWS_PROFILE=other-account terraform apply -var-file=terraform.tfvars
```

Ensure CloudTrail is set up in each target account. SNS subscriptions (FinOps DL, Team DL) must be confirmed via the emails AWS sends.

## Deploy with Terraform via GitHub Actions

This repository includes GitHub Actions workflows that let any team member deploy the Tag Compliance Scanner to any configured AWS account using the same pattern as the example Terraform repo.

### 1. Configure per-account settings

For each environment/account, create an `account.tfvars` file:

```text
env/<environment>/<account>/account.tfvars
```

This repo already includes examples for:

- `env/dev/347116755583/account.tfvars`
- `env/prod/173534767488/account.tfvars`

Each file should define at least:

```hcl
aws_account_id  = "<12-digit-account-id>"
aws_region      = "us-east-1"
assume_role_arn = "arn:aws:iam::<account-id>:role/github-terraform-aws"

tf_state_bucket = "<s3-bucket-for-terraform-state>"
tf_state_region = "us-east-1"

fallback_finops_dl = "finops@yourcompany.com"
terraform_team_dl  = "cloud-team@yourcompany.com"
```

You can also override any Terraform variables defined in `terraform/variables.tf` (for example `platform_app_dl`, `region_scope`, or `analytics_retention_days`) by adding them to the same `account.tfvars` file.

### 2. AWS IAM and OIDC requirements

For each AWS account you want to target:

- Configure a GitHub OIDC trust relationship and create an IAM role such as `github-terraform-aws`.
- Grant that role permissions to manage the resources defined in `terraform/` (Lambda, DynamoDB, SNS, EventBridge, and the analytics S3 bucket).
- Use the ARN of that role as `assume_role_arn` in the corresponding `account.tfvars`.

The Terraform state for each environment/account is stored in the S3 bucket specified by `tf_state_bucket`, under a key:

```text
tag-compliance/<environment>/<account>/terraform.tfstate
```

Make sure the state bucket exists and is accessible by the IAM role.

### 3. Workflows

There are two workflows under `.github/workflows/`:

- `List Tag Compliance Configurations` (`list-configs.yml`):
  - Trigger: `workflow_dispatch`.
  - Input: `environment` (`all`, `dev`, or `prod`).
  - Output: a table in the job summary listing `env/<environment>/<account>/account.tfvars` files.

- `Terraform Tag Compliance Scanner` (`terraform.yml`):
  - Trigger: `workflow_dispatch`.
  - Inputs:
    - `action`: `plan`, `apply`, or `destroy`
    - `environment`: `dev` or `prod`
    - `account`: 12-digit AWS account ID
  - Behavior:
    - Validates that `env/<environment>/<account>/account.tfvars` exists.
    - Parses `assume_role_arn`, `aws_region`, `tf_state_bucket`, and `tf_state_region`.
    - Assumes the IAM role via GitHub OIDC.
    - Runs `terraform init`, `terraform validate`, and `terraform plan`/`apply`/`destroy` in the `terraform/` directory using the selected `account.tfvars`.
    - Writes a summary (inputs, state bucket, result) to the GitHub Actions job summary.

### 4. Example GitHub deployment flow

1. Ensure `env/dev/<account>/account.tfvars` is configured and the IAM role/state bucket exist.
2. In GitHub, go to **Actions** → **Terraform Tag Compliance Scanner**.
3. Choose:
   - `action` = `plan`
   - `environment` = `dev`
   - `account` = `<12-digit-account-id>`
4. Run the workflow and review the Terraform plan.
5. Re-run the workflow with `action` = `apply` to deploy.

### 5. How to add another AWS account

To target an additional AWS account from the workflow:

1. **Choose environment and account ID**
   - Decide whether this account is `dev` or `prod` (must match the `environment` input you will use in the workflow).
   - Note the 12-digit AWS account ID (for example `503532613196`).
   - Create a folder: `env/<environment>/<account-id>/` (for example `env/dev/503532613196/`).

2. **Create `account.tfvars` for that account**
   - In the new folder, create `account.tfvars`:

   ```hcl
   aws_account_id  = "503532613196"
   aws_region      = "us-east-1"

   # IAM role in that account that GitHub will assume via OIDC
   assume_role_arn = "arn:aws:iam::503532613196:role/github-terraform-aws"

   # S3 bucket that will hold Terraform state for this stack
   tf_state_bucket = "ns-terraform-state-503532613196-us-east-1"
   tf_state_region = "us-east-1"

   # Required emails for this Terraform stack
   fallback_finops_dl = "finops@yourcompany.com"
   terraform_team_dl  = "cloud-team@yourcompany.com"

   tags = {
     app-name    = "tag-compliance-scanner"
     environment = "dev" # or "prod" if under env/prod
     ManagedBy   = "terraform"
   }
   ```

   - You may override any optional variables from `terraform/variables.tf` (for example `platform_app_dl`, `region_scope`, or `analytics_retention_days`) in this same file if needed.

3. **Prepare the AWS account**
   - In the target AWS account:
     - Create or reuse the IAM role referenced in `assume_role_arn` and configure GitHub OIDC trust.
     - Attach a policy that allows that role to manage the resources defined in `terraform/` (Lambda, DynamoDB, SNS, EventBridge, and the analytics S3 bucket).
     - Create the S3 bucket named in `tf_state_bucket` in `tf_state_region` and allow the role to read/write state objects.

4. **Use the new account in the workflow**
   - Commit and push the new `env/<environment>/<account-id>/account.tfvars`.
   - In GitHub, go to **Actions** → **Terraform Tag Compliance Scanner**.
   - Click **Run workflow** and select:
     - `action`: `plan`, `apply`, or `destroy`
     - `environment`: `dev` or `prod` (matching the folder you used)
     - `account`: the 12-digit account ID you just added
   - The workflow will automatically:
     - Validate that `env/<environment>/<account>/account.tfvars` exists.
     - Parse `assume_role_arn`, `aws_region`, `tf_state_bucket`, and `tf_state_region` from that file.
     - Assume the IAM role and run Terraform against that AWS account.


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
