"""
EC2 tag compliance scanner: scan EC2 instances, check required tags from
Cloud Tagging Policy. For each non-compliant instance, resolve recipient:
OwnerEmail tag, else CloudTrail creator → Human (email user), Terraform (team DL),
CI/CD (team DL), Unknown (Cloud/FinOps DL). Sends emails via SES.

Escalation: Day 0 → email creator; Day 3 → reminder; Day 5 → escalate to FinOps/creator.
State tracked in DynamoDB. Auto-close when tags fixed.

Enhancement:
- If creator is an AWS SSO (IAM Identity Center) session (role starts with AWSReservedSSO_),
  email the SSO user's email from the session name.
"""
import os
import re
import json
import logging
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Required tag keys from Cloud Tagging Policy (env or default)
_DEFAULT_REQUIRED_TAGS = (
    "app-name,created-by,app-owner,infra-owner,department,environment,"
    "schedule,compliance,data-classification,project-id,servicenow-asset-tracking,expense-type"
)
REQUIRED_TAGS = [
    k.strip()
    for k in os.environ.get("REQUIRED_TAGS", _DEFAULT_REQUIRED_TAGS).split(",")
    if k.strip()
]

# Recipient addresses (env or defaults). Human → user email via EMAIL_DOMAIN only (no DynamoDB).
TEAM_DL = os.environ.get("TEAM_DL", "team-dl@example.com")   # Terraform/CI-CD/assumed roles
FINOPS_DL = os.environ.get("FINOPS_DL", "finops-dl@example.com")  # Unknown / no trail
PLATFORM_APP_DL = os.environ.get("PLATFORM_APP_DL", "") or FINOPS_DL
EMAIL_DOMAIN = os.environ.get("EMAIL_DOMAIN", "")
LOOKBACK_DAYS = int(os.environ.get("CLOUDTRAIL_LOOKBACK_DAYS", "30"))
REGION_SCOPE = os.environ.get("REGION_SCOPE", "")
STATE_TABLE = os.environ.get("STATE_TABLE", "")
SES_FROM_ADDRESS = os.environ.get("SES_FROM_ADDRESS", "")


def regions_to_scan():
    """Current region only, or all regions if REGION_SCOPE == 'all'."""
    if REGION_SCOPE and REGION_SCOPE.lower() == "all":
        ec2 = boto3.client("ec2")
        return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
    return [os.environ.get("AWS_REGION", "us-east-1")]


def _state_pk(instance_id: str, region: str) -> str:
    """DynamoDB pk for compliance state: instance:{id}:{region}."""
    return f"instance:{instance_id}:{region}"


def _get_state_from_dynamodb(instance_id: str, region: str) -> dict | None:
    """Read compliance state from DynamoDB. Returns None if no state table or no row."""
    if not STATE_TABLE:
        return None
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(STATE_TABLE)
        resp = table.get_item(
            Key={"pk": _state_pk(instance_id, region), "sk": "state"},
        )
        return resp.get("Item")
    except ClientError as e:
        logger.warning("DynamoDB get failed for %s in %s: %s", instance_id, region, e)
        return None


def _update_state_in_dynamodb(
    instance_id: str,
    region: str,
    *,
    first_detected_at: str | None = None,
    last_notified_at: str | None = None,
    stage: str | None = None,
    recipient: str | None = None,
    recipient_reason: str | None = None,
    missing_tags: list | None = None,
) -> None:
    """Create or update compliance state in DynamoDB."""
    if not STATE_TABLE:
        return
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(STATE_TABLE)
        now = datetime.now(timezone.utc).isoformat()
        pk, sk = _state_pk(instance_id, region), "state"

        update_expr_parts = []
        expr_names = {}
        expr_values = {}

        if first_detected_at is not None:
            update_expr_parts.append("#fd = :fd")
            expr_names["#fd"] = "firstDetectedAt"
            expr_values[":fd"] = first_detected_at
        if last_notified_at is not None:
            update_expr_parts.append("#ln = :ln")
            expr_names["#ln"] = "lastNotifiedAt"
            expr_values[":ln"] = last_notified_at
        if stage is not None:
            update_expr_parts.append("#st = :st")
            expr_names["#st"] = "stage"
            expr_values[":st"] = stage
        if recipient is not None:
            update_expr_parts.append("#rc = :rc")
            expr_names["#rc"] = "recipient"
            expr_values[":rc"] = recipient
        if recipient_reason is not None:
            update_expr_parts.append("#rr = :rr")
            expr_names["#rr"] = "recipientReason"
            expr_values[":rr"] = recipient_reason
        if missing_tags is not None:
            update_expr_parts.append("#mt = :mt")
            expr_names["#mt"] = "missingTags"
            expr_values[":mt"] = missing_tags

        update_expr_parts.append("#up = :up")
        expr_names["#up"] = "updatedAt"
        expr_values[":up"] = now

        if update_expr_parts:
            update_expr = "SET " + ", ".join(update_expr_parts)
            table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
            )
    except ClientError as e:
        logger.warning("DynamoDB update failed for %s in %s: %s", instance_id, region, e)


def _put_initial_state_in_dynamodb(
    instance_id: str,
    region: str,
    recipient: str,
    recipient_reason: str,
    missing_tags: list,
) -> None:
    """Put initial Day 0 state (create new row)."""
    if not STATE_TABLE:
        return
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(STATE_TABLE)
        now = datetime.now(timezone.utc).isoformat()
        table.put_item(
            Item={
                "pk": _state_pk(instance_id, region),
                "sk": "state",
                "firstDetectedAt": now,
                "lastNotifiedAt": now,
                "stage": "day0",
                "recipient": recipient,
                "recipientReason": recipient_reason,
                "missingTags": missing_tags,
                "updatedAt": now,
            }
        )
    except ClientError as e:
        logger.warning("DynamoDB put failed for %s in %s: %s", instance_id, region, e)


def _close_state_in_dynamodb(instance_id: str, region: str) -> None:
    """Mark state as closed (tags fixed). Sets closedAt for TTL cleanup."""
    if not STATE_TABLE:
        return
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(STATE_TABLE)
        now = datetime.now(timezone.utc).isoformat()
        # TTL: 30 days from now (Unix timestamp)
        ttl_seconds = int(datetime.now(timezone.utc).timestamp()) + 30 * 24 * 3600
        table.update_item(
            Key={"pk": _state_pk(instance_id, region), "sk": "state"},
            UpdateExpression="SET #st = :closed, #ca = :now, closedAtTTL = :ttl",
            ExpressionAttributeNames={"#st": "stage", "#ca": "closedAt"},
            ExpressionAttributeValues={
                ":closed": "closed",
                ":now": now,
                ":ttl": ttl_seconds,
            },
        )
    except ClientError as e:
        logger.warning("DynamoDB close failed for %s in %s: %s", instance_id, region, e)


def _days_since(first_detected_at: str) -> int:
    """Compute whole days since firstDetectedAt (ISO string)."""
    try:
        dt = datetime.fromisoformat(first_detected_at.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - dt
        return max(0, delta.days)
    except (ValueError, TypeError):
        return 0


def _subject_for_stage(instance_id: str, missing_count: int, stage: str) -> str:
    """Subject line for Day 0 / Day 3 / Day 5."""
    if stage == "day0":
        return f"[ACTION REQUIRED] EC2 tag compliance: missing {missing_count} tag(s) on {instance_id}"
    if stage == "day3":
        return f"[REMINDER] EC2 tag compliance: {instance_id} still missing {missing_count} tag(s)"
    if stage == "day5":
        return f"[ESCALATION] EC2 tag compliance: {instance_id} non-compliant 5+ days"
    return f"[ACTION REQUIRED] EC2 tag compliance: missing {missing_count} tag(s) on {instance_id}"


def lambda_handler(event, context):
    """Scan EC2 instances, resolve recipient, send emails via SES, track state in DynamoDB (Day 0/3/5 escalation)."""
    logger.info("Starting EC2 tag compliance scan; regions=%s", regions_to_scan())
    total_scanned = total_noncompliant = total_notified = 0

    for region in regions_to_scan():
        ec2 = boto3.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    state_name = inst.get("State", {}).get("Name")
                    if state_name in ("terminated", "shutting-down"):
                        continue

                    total_scanned += 1
                    instance_id = inst["InstanceId"]
                    tags = (
                        {t["Key"]: t.get("Value", "") for t in inst.get("Tags", [])}
                        if inst.get("Tags")
                        else {}
                    )
                    missing = [k for k in REQUIRED_TAGS if not _tag_present(tags, k)]

                    try:
                        if not missing:
                            # Compliant: auto-close if state exists
                            state = _get_state_from_dynamodb(instance_id, region)
                            if state and state.get("stage") != "closed":
                                _close_state_in_dynamodb(instance_id, region)
                                logger.info("Auto-closed: %s in %s (tags fixed)", instance_id, region)
                            continue

                        total_noncompliant += 1
                        recipient, reason = _resolve_recipient(inst, tags, region)
                        state = _get_state_from_dynamodb(instance_id, region)

                        now = datetime.now(timezone.utc).isoformat()
                        recipients_to_email = [recipient]
                        stage_to_send = "day0"

                        if not state:
                            # Day 0: new detection
                            _put_initial_state_in_dynamodb(instance_id, region, recipient, reason, missing)
                            stage_to_send = "day0"
                        else:
                            first_at = state.get("firstDetectedAt") or now
                            days = _days_since(first_at)
                            current_stage = state.get("stage") or "day0"

                            if days >= 5 and current_stage != "day5":
                                # Escalate to Day 5 (one-time)
                                stage_to_send = "day5"
                                recipients_to_email = list({recipient, FINOPS_DL})
                                _update_state_in_dynamodb(
                                    instance_id, region,
                                    last_notified_at=now, stage="day5",
                                    recipient=recipient, recipient_reason=reason, missing_tags=missing,
                                )
                            elif days >= 3 and current_stage == "day0":
                                # Day 3 reminder
                                stage_to_send = "day3"
                                _update_state_in_dynamodb(
                                    instance_id, region,
                                    last_notified_at=now, stage="day3",
                                    recipient=recipient, recipient_reason=reason, missing_tags=missing,
                                )
                            else:
                                # Day 0-2: no action; Day 3 already sent; Day 5 already sent
                                continue

                        subject = _subject_for_stage(instance_id, len(missing), stage_to_send)
                        body = _build_body(instance_id, region, tags, missing, recipient, reason, stage=stage_to_send)
                        if _send_email_via_ses(recipients_to_email, subject, body):
                            total_notified += 1
                    except Exception as e:
                        logger.warning("Error processing instance %s in %s: %s", instance_id, region, e, exc_info=True)

    logger.info("Scan complete. scanned=%d noncompliant=%d notified=%d", total_scanned, total_noncompliant, total_notified)
    return {
        "scanned": total_scanned,
        "noncompliant": total_noncompliant,
        "notified": total_notified,
    }


def _send_email_via_ses(
    recipients: list[str],
    subject: str,
    body: str,
) -> bool:
    """Send email via SES. Returns True on success, False on failure."""
    if not SES_FROM_ADDRESS or not recipients:
        logger.warning("SES send skipped: missing SES_FROM_ADDRESS or recipients")
        return False
    recipients = [r.strip() for r in recipients if r and r.strip()]
    if not recipients:
        return False
    try:
        ses = boto3.client("ses")
        ses.send_email(
            Source=SES_FROM_ADDRESS,
            Destination={"ToAddresses": recipients},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
            },
        )
        logger.info("SES email sent to %s: %s", recipients, subject)
        return True
    except ClientError as e:
        logger.warning("SES send failed: %s", e)
        return False


def _tag_present(tags: dict, key: str) -> bool:
    """True if key exists and value is non-empty."""
    v = tags.get(key)
    return v is not None and str(v).strip() != ""


def _resolve_recipient(inst: dict, tags: dict, region: str) -> tuple[str, str]:
    """
    1) OwnerEmail tag → email that person
    2) Else CloudTrail LookupEvents → classify creator:
       - Human IAM user → if username looks like email, use it; else FINOPS_DL
       - Human SSO (AWSReservedSSO_ role) → email user (sessionName)
       - Terraform role / CI/CD role / any other assumed role (not SSO) → TEAM_DL
       - AWSService (EC2 created by an AWS service) → TEAM_DL
       - Unknown / no trail → FINOPS_DL (last resort)
    Returns (email_address_or_identifier, reason_string).
    """
    # 1) OwnerEmail tag
    for key in ["OwnerEmail", "ownerEmail", "owner-email", "owner_email", "Owner", "NSAppOwner"]:
        val = tags.get(key)
        if val and _looks_like_email(val):
            return val.strip(), f"OwnerEmail tag ({key})"

    # 2) CloudTrail: who created the resource
    creator = _find_creator_via_cloudtrail(inst["InstanceId"], region)
    if not creator:
        return FINOPS_DL, "Cloud/FinOps DL (no trail / unknown creator)"

    classification = _classify_creator(creator)
    if classification == "human":
        username = creator.get("userName") or creator.get("principalId") or "unknown"
        email = _user_to_email(username)
        if email:
            return email, f"Human IAM user ({username})"
        return FINOPS_DL, f"Human IAM user ({username}) — no email mapping, using FinOps DL"

    # 🔹 NEW: direct SSO human routing
    if classification == "human_sso":
        email = creator.get("sessionName") or ""
        if _looks_like_email(email):
            return email, f"Human SSO user ({email})"
        # Fallback if session name is not an email for some reason
        role_name = creator.get("roleName") or "unknown"
        return FINOPS_DL, f"SSO role ({role_name}) — session not an email, using FinOps DL"

    if classification == "terraform":
        role_name = creator.get("roleName") or "unknown"
        return TEAM_DL, f"Terraform role ({role_name}) → Team DL"

    if classification == "cicd":
        role_name = creator.get("roleName") or "unknown"
        return TEAM_DL, f"CI/CD role ({role_name}) → Team DL"

    if classification == "assumed_role":
        # Assumed role but not SSO → Team DL
        role_name = creator.get("roleName") or "unknown"
        return TEAM_DL, f"Assumed role ({role_name}) → Team DL"

    if classification == "aws_service":
        # EC2 created by an AWS service → Team DL
        return TEAM_DL, "AWS service (creator) → Team DL"

    # unknown / no trail → Cloud/FinOps DL (last resort)
    return FINOPS_DL, f"Creator type {creator.get('type')} → Cloud/FinOps DL"


def _classify_creator(creator: dict) -> str:
    """
    Classify CloudTrail userIdentity as human | human_sso | terraform | cicd | assumed_role | aws_service | unknown.
    - IAMUser → human
    - AWSService (AWS service created the resource) → aws_service → Team DL
    - AssumedRole + SSO (AWSReservedSSO_ + session looks like email) → human_sso (email user)
    - AssumedRole + "terraform" in role/session → terraform → Team DL
    - AssumedRole + cicd markers in role/session → cicd → Team DL
    - AssumedRole but not SSO (any other assumed role) → assumed_role → Team DL
    - No trail / root / etc. → unknown → Cloud/FinOps DL (last resort)
    """
    identity_type = (creator.get("type") or "").strip()
    if identity_type == "IAMUser":
        return "human"

    if identity_type == "AWSService":
        return "aws_service"

    if identity_type != "AssumedRole":
        return "unknown"

    role_name_raw = creator.get("roleName") or ""
    session_name_raw = creator.get("sessionName") or ""
    role_name = role_name_raw.lower()
    session_name = session_name_raw.lower()

    # SSO (IAM Identity Center): email the user
    if role_name.startswith("awsreservedsso_") and _looks_like_email(session_name_raw):
        return "human_sso"

    terraform_markers = ["terraform"]
    cicd_markers = ["cicd", "ci-cd", "pipeline", "jenkins", "github", "gitlab"]

    if any(m in role_name or m in session_name for m in terraform_markers):
        return "terraform"
    if any(m in role_name or m in session_name for m in cicd_markers):
        return "cicd"

    # Assumed role but not SSO → Team DL (Terraform/CI-CD/other automation or human-assumed role)
    return "assumed_role"


def _find_creator_via_cloudtrail(instance_id: str, region: str) -> dict | None:
    """Use CloudTrail LookupEvents to find who created the EC2 instance (RunInstances)."""
    try:
        cloudtrail = boto3.client("cloudtrail", region_name=region)
        start = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
        events = []
        paginator = cloudtrail.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": instance_id},
            ],
            StartTime=start,
        ):
            events.extend(page.get("Events", []))

        if not events:
            return None

        # Prefer RunInstances; else earliest event
        run_instances = [e for e in events if _event_name(e) == "RunInstances"]
        chosen = min(run_instances, key=lambda e: e["EventTime"]) if run_instances else min(events, key=lambda e: e["EventTime"])
        detail = json.loads(chosen.get("CloudTrailEvent", "{}"))
        ui = detail.get("userIdentity", {}) or {}

        identity_type = ui.get("type", "Unknown")
        user_name = ui.get("userName")
        principal_id = ui.get("principalId")
        arn = ui.get("arn", "")
        role_name = session_name = None
        if ":assumed-role/" in arn:
            parts = arn.split("/")
            if len(parts) >= 3:
                role_name = parts[-2]
                session_name = parts[-1]

        return {
            "type": identity_type,
            "userName": user_name,
            "principalId": principal_id,
            "arn": arn,
            "roleName": role_name,
            "sessionName": session_name,
        }
    except ClientError as e:
        logger.warning("CloudTrail lookup failed for %s in %s: %s", instance_id, region, e)
        return None


def _event_name(event: dict) -> str:
    """Get event name from CloudTrail event (eventName in CloudTrailEvent JSON)."""
    try:
        detail = json.loads(event.get("CloudTrailEvent", "{}"))
        return detail.get("eventName", "")
    except Exception:
        return ""


def _user_to_email(username: str) -> str | None:
    """Resolve IAM username to email ONLY if it already looks like an email."""
    if not username or not username.strip():
        return None
    username = username.strip()
    return username if _looks_like_email(username) else None


def _looks_like_email(s: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", str(s).strip()))


def _build_body(
    instance_id: str,
    region: str,
    tags: dict,
    missing: list,
    recipient: str,
    reason: str,
    stage: str = "day0",
) -> str:
    """Plain-text email body. stage: day0 | day3 | day5 for escalation context."""
    intro_map = {
        "day0": f"EC2 instance {instance_id} in region {region} is missing required tags. This is your initial notification.",
        "day3": f"REMINDER: EC2 instance {instance_id} in region {region} is still missing required tags (3+ days since first detection).",
        "day5": f"ESCALATION: EC2 instance {instance_id} in region {region} has been non-compliant for 5+ days. This case is escalated to FinOps/Team Lead.",
    }
    intro = intro_map.get(stage, intro_map["day0"])
    lines = [
        intro,
        "",
        "--- Existing tags (current key-value pairs) ---",
    ]
    if tags:
        for k, v in sorted(tags.items()):
            lines.append(f"  {k}: {v}")
    else:
        lines.append("  (none)")
    lines.extend(["", "--- Tags that need to be added ---"])
    for k in missing:
        lines.append(f"  {k}: <add value per Cloud Tagging Policy>")
    lines.extend(
        [
            "",
            f"Notification sent to: {recipient} ({reason})",
            "",
            "Required tags are defined in the Cloud Tagging Policy.",
            "Add the missing tags in EC2 Console: Instances → select instance → Tags → Manage tags.",
            "",
            "This is an automated compliance notice.",
        ]
    )
    return "\n".join(lines)
