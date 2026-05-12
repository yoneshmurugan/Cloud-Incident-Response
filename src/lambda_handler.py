"""
Cloud Incident Response Pipeline — Lambda Handler
Triggered by EventBridge on GuardDuty high-severity EC2 findings.
Executes: EBS snapshot | SG isolation | IAM credential revocation
"""
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

QUARANTINE_SG_ID: str = os.environ["QUARANTINE_SG_ID"]
AWS_REGION: str = os.environ.get("AWS_REGION", "us-east-1")

ec2_client = boto3.client("ec2", region_name=AWS_REGION)
iam_client = boto3.client("iam")

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Main entry point. Extracts instance metadata from GuardDuty
    finding and dispatches all three containment actions.
    """
    logger.info("IR Pipeline triggered", extra={"event": json.dumps(event)})
    
    detail = event.get("detail", {})
    finding_id = detail.get("id", "unknown")
    finding_type = detail.get("type", "unknown")
    severity = detail.get("severity", 0)
    
    instance_details = detail.get("resource", {}).get("instanceDetails", {})
    instance_id = instance_details.get("instanceId")
    profile_arn = instance_details.get("iamInstanceProfile", {}).get("arn", "")

    if not instance_id:
        logger.error("No instanceId in event — aborting.", extra={"finding_id": finding_id})
        return {"statusCode": 400, "body": "Missing instanceId"}

    logger.info(
        "Responding to finding",
        extra={"instance_id": instance_id, "finding_type": finding_type,
               "severity": severity, "finding_id": finding_id}
    )

    role_name = _extract_role_name(profile_arn)

    # Run all three actions concurrently
    results: dict[str, Any] = {}
    actions = {
        "snapshot": lambda: trigger_ebs_snapshot(instance_id, finding_id),
        "isolation": lambda: isolate_instance(instance_id),
        "revocation": lambda: revoke_iam_credentials(role_name, finding_id) if role_name else "NO_ROLE_FOUND",
    }

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(fn): name for name, fn in actions.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                logger.error(f"Action {name} failed: {exc}")
                results[name] = f"FAILED: {exc}"

    logger.info("IR actions complete", extra={"results": results})
    return {"statusCode": 200, "body": json.dumps(results)}

# --- Helper: Extract Role Name ---
def _extract_role_name(profile_arn: str) -> str | None:
    """
    Parses role name from instance profile ARN.
    """
    if not profile_arn:
        return None
    match = re.search(r"instance-profile/(.+)$", profile_arn)
    if match:
        profile_name = match.group(1)
        try:
            resp = iam_client.get_instance_profile(InstanceProfileName=profile_name)
            roles = resp["InstanceProfile"]["Roles"]
            return roles[0]["RoleName"] if roles else None
        except ClientError as e:
            logger.warning(f"Could not resolve role from profile: {e}")
            return None

# --- Action 1: EBS Forensic Snapshot ---
def trigger_ebs_snapshot(instance_id: str, finding_id: str) -> str:
    """
    Creates an EBS snapshot for all attached volumes.
    """
    volumes = ec2_client.describe_volumes(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
    )["Volumes"]
    
    snapshot_ids: list[str] = []
    for volume in volumes:
        volume_id = volume["VolumeId"]
        existing = ec2_client.describe_snapshots(
            Filters=[
                {"Name": "volume-id", "Values": [volume_id]},
                {"Name": "tag:FindingId", "Values": [finding_id]},
                {"Name": "status", "Values": ["pending", "completed"]},
            ],
            OwnerIds=["self"]
        )["Snapshots"]
        
        if existing:
            snap_id = existing[0]["SnapshotId"]
            logger.info(f"Snapshot already exists for {volume_id}: {snap_id}")
            snapshot_ids.append(snap_id)
            continue
            
        snap = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"IR-FORENSIC | Instance:{instance_id} | Finding:{finding_id}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "Project", "Value": "cloud-ir-pipeline"},
                    {"Key": "Purpose", "Value": "forensics"},
                    {"Key": "InstanceId", "Value": instance_id},
                    {"Key": "FindingId", "Value": finding_id},
                ]
            }]
        )
        snapshot_ids.append(snap["SnapshotId"])
        logger.info(f"Snapshot created: {snap['SnapshotId']} for volume {volume_id}")
        
    return f"SNAPSHOTS:{snapshot_ids}"

# --- Action 2: Network Isolation ---
def isolate_instance(instance_id: str) -> str:
    """
    Replaces all Security Groups on the instance with the quarantine blackhole SG.
    """
    instance = ec2_client.describe_instances(
        InstanceIds=[instance_id]
    )["Reservations"][0]["Instances"][0]
    
    current_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
    if current_sgs == [QUARANTINE_SG_ID]:
        logger.info(f"Instance {instance_id} already quarantined — skipping SG swap.")
        return "ALREADY_ISOLATED"
        
    ec2_client.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG_ID]
    )
    logger.info(f"SG swap complete on {instance_id}", extra={"from": current_sgs, "to": QUARANTINE_SG_ID})
    return f"ISOLATED: {QUARANTINE_SG_ID}"

# --- Action 3: IAM Credential Revocation ---
def revoke_iam_credentials(role_name: str, finding_id: str) -> str:
    """
    Attaches a Deny-All inline policy to the instance role.
    """
    DENY_POLICY_NAME = "IR-EmergencyDenyAll"
    DENY_POLICY_DOC = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "IREmergencyDenyAll",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:RequestedRegion": ["*"]}
            }
        }]
    })
    
    try:
        existing = iam_client.get_role_policy(
            RoleName=role_name,
            PolicyName=DENY_POLICY_NAME
        )
        logger.info(f"Deny policy already on role {role_name} — skipping.")
        return "ALREADY_REVOKED"
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
            
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=DENY_POLICY_NAME,
            PolicyDocument=DENY_POLICY_DOC
        )
        logger.info(f"Deny-All inline policy attached to role {role_name}", extra={"finding_id": finding_id})
        return f"REVOKED: {role_name}"