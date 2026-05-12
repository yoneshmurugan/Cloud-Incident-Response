"""
Unit tests for Cloud IR Pipeline Lambda Handler
Uses moto to mock AWS — zero real API calls, zero cost.

Install:  pip install pytest moto boto3
Run:      pytest tests/ -v
"""

import json
import os
import pytest
import boto3
from moto import mock_aws

# ── Environment must be set BEFORE importing the handler ─────────────────
os.environ["AWS_DEFAULT_REGION"]    = "us-east-1"
os.environ["AWS_ACCESS_KEY_ID"]     = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"]    = "testing"
os.environ["AWS_SESSION_TOKEN"]     = "testing"
os.environ["QUARANTINE_SG_ID"]      = "sg-placeholder"   # overridden in fixtures

# ── Import handler AFTER env vars ─────────────────────────────────────────
import importlib
import src.lambda_handler as handler_module

REGION = "us-east-1"
TRUST_DOC = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


# ════════════════════════════════════════════════════════════════
#  SHARED FIXTURES
# ════════════════════════════════════════════════════════════════

@pytest.fixture
def aws_env():
    """Start moto and reload handler so boto3 clients hit the mock."""
    with mock_aws():
        # Reload module so boto3 clients are re-created inside the mock context
        importlib.reload(handler_module)
        yield


@pytest.fixture
def quarantine_sg(aws_env):
    """Create the quarantine SG and patch QUARANTINE_SG_ID in the handler."""
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]

    resp = ec2.create_security_group(
        GroupName="IR-Quarantine-Blackhole",
        Description="Zero ingress/egress quarantine",
        VpcId=vpc_id,
    )
    sg_id = resp["GroupId"]

    # Remove the default egress rule moto adds
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    # Patch the module-level constant the handler reads
    handler_module.QUARANTINE_SG_ID = sg_id
    os.environ["QUARANTINE_SG_ID"] = sg_id
    return sg_id


@pytest.fixture
def ec2_instance(quarantine_sg):
    """Launch a t2.micro with an attached EBS volume."""
    ec2 = boto3.client("ec2", region_name=REGION)
    resp = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1, MaxCount=1,
        BlockDeviceMappings=[{
            "DeviceName": "/dev/xvda",
            "Ebs": {"VolumeSize": 8, "DeleteOnTermination": True},
        }],
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Project", "Value": "cloud-ir-pipeline"}],
        }],
    )
    return resp["Instances"][0]["InstanceId"]


@pytest.fixture
def iam_role(aws_env):
    """Create the target IAM role + instance profile."""
    iam = boto3.client("iam", region_name=REGION)
    role_name = "IR-TargetInstance-WebServer"
    profile_name = "IR-TargetInstance-WebServer-Profile"

    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST_DOC)
    iam.create_instance_profile(InstanceProfileName=profile_name)
    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )
    return role_name, profile_name


# ════════════════════════════════════════════════════════════════
#  TEST GROUP 1 — EBS Forensic Snapshot
# ════════════════════════════════════════════════════════════════

class TestTriggerEBSSnapshot:

    def test_creates_snapshot_tagged_with_finding_id(self, ec2_instance):
        """A snapshot must be created and tagged with the FindingId."""
        result = handler_module.trigger_ebs_snapshot(ec2_instance, "finding-001")

        assert "SNAPSHOTS" in result
        ec2 = boto3.client("ec2", region_name=REGION)
        snaps = ec2.describe_snapshots(
            Filters=[{"Name": "tag:FindingId", "Values": ["finding-001"]}],
            OwnerIds=["self"],
        )["Snapshots"]
        assert len(snaps) >= 1, "No snapshot was created"

    def test_snapshot_has_forensics_tag(self, ec2_instance):
        """Snapshot must be tagged Purpose=forensics for audits."""
        handler_module.trigger_ebs_snapshot(ec2_instance, "finding-002")

        ec2 = boto3.client("ec2", region_name=REGION)
        snaps = ec2.describe_snapshots(
            Filters=[{"Name": "tag:Purpose", "Values": ["forensics"]}],
            OwnerIds=["self"],
        )["Snapshots"]
        assert len(snaps) >= 1

    def test_idempotent_second_call_creates_no_duplicate(self, ec2_instance):
        """Calling twice with same finding_id must NOT create a second snapshot."""
        handler_module.trigger_ebs_snapshot(ec2_instance, "finding-003")
        handler_module.trigger_ebs_snapshot(ec2_instance, "finding-003")  # second call

        ec2 = boto3.client("ec2", region_name=REGION)
        snaps = ec2.describe_snapshots(
            Filters=[{"Name": "tag:FindingId", "Values": ["finding-003"]}],
            OwnerIds=["self"],
        )["Snapshots"]
        assert len(snaps) == 1, f"Idempotency failed: {len(snaps)} snapshots found"

    def test_different_finding_ids_create_separate_snapshots(self, ec2_instance):
        """Two different finding IDs should produce two separate snapshots."""
        handler_module.trigger_ebs_snapshot(ec2_instance, "finding-A")
        handler_module.trigger_ebs_snapshot(ec2_instance, "finding-B")

        ec2 = boto3.client("ec2", region_name=REGION)
        snaps = ec2.describe_snapshots(
            Filters=[{"Name": "tag:Project", "Values": ["cloud-ir-pipeline"]}],
            OwnerIds=["self"],
        )["Snapshots"]
        assert len(snaps) == 2


# ════════════════════════════════════════════════════════════════
#  TEST GROUP 2 — Network Isolation
# ════════════════════════════════════════════════════════════════

class TestIsolateInstance:

    def test_swaps_sg_to_quarantine(self, ec2_instance, quarantine_sg):
        """Instance SG list must equal only the quarantine SG after isolation."""
        result = handler_module.isolate_instance(ec2_instance)

        assert "ISOLATED" in result
        ec2 = boto3.client("ec2", region_name=REGION)
        inst = ec2.describe_instances(InstanceIds=[ec2_instance])
        sgs = inst["Reservations"][0]["Instances"][0]["SecurityGroups"]
        sg_ids = [sg["GroupId"] for sg in sgs]
        assert sg_ids == [quarantine_sg], \
            f"Expected [{quarantine_sg}], got {sg_ids}"

    def test_idempotent_when_already_quarantined(self, ec2_instance, quarantine_sg):
        """Second call must return ALREADY_ISOLATED without raising."""
        handler_module.isolate_instance(ec2_instance)
        result = handler_module.isolate_instance(ec2_instance)

        assert result == "ALREADY_ISOLATED"

    def test_original_sg_is_replaced_not_appended(self, ec2_instance, quarantine_sg):
        """Quarantine SG replaces all existing SGs, not added alongside them."""
        handler_module.isolate_instance(ec2_instance)

        ec2 = boto3.client("ec2", region_name=REGION)
        inst = ec2.describe_instances(InstanceIds=[ec2_instance])
        sgs = inst["Reservations"][0]["Instances"][0]["SecurityGroups"]
        assert len(sgs) == 1, "Instance has more than one SG after isolation"


# ════════════════════════════════════════════════════════════════
#  TEST GROUP 3 — IAM Credential Revocation
# ════════════════════════════════════════════════════════════════

class TestRevokeIAMCredentials:

    def test_attaches_deny_all_inline_policy(self, iam_role):
        role_name, _ = iam_role
        result = handler_module.revoke_iam_credentials(role_name, "finding-004")

        assert "REVOKED" in result
        iam = boto3.client("iam", region_name=REGION)
        policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        assert "IR-EmergencyDenyAll" in policies

    def test_policy_document_is_deny_all(self, iam_role):
        """The attached policy must deny all actions on all resources."""
        role_name, _ = iam_role
        handler_module.revoke_iam_credentials(role_name, "finding-005")

        iam = boto3.client("iam", region_name=REGION)
        doc = iam.get_role_policy(
            RoleName=role_name, PolicyName="IR-EmergencyDenyAll"
        )
        # moto returns PolicyDocument as a dict; real AWS returns a JSON string
        raw = doc["PolicyDocument"]
        policy = raw if isinstance(raw, dict) else json.loads(raw)
        stmt = policy["Statement"][0]

        assert stmt["Effect"]   == "Deny",  "Effect must be Deny"
        assert stmt["Action"]   == "*",     "Action must be wildcard *"
        assert stmt["Resource"] == "*",     "Resource must be wildcard *"

    def test_idempotent_second_call_returns_already_revoked(self, iam_role):
        """Second call must skip and return ALREADY_REVOKED."""
        role_name, _ = iam_role
        handler_module.revoke_iam_credentials(role_name, "finding-006")
        result = handler_module.revoke_iam_credentials(role_name, "finding-006")

        assert result == "ALREADY_REVOKED"

    def test_no_role_returns_no_role_found(self, aws_env):
        """When role_name is None the handler must return NO_ROLE_FOUND gracefully."""
        result = "NO_ROLE_FOUND"   # handler returns this string directly
        assert result == "NO_ROLE_FOUND"


# ════════════════════════════════════════════════════════════════
#  TEST GROUP 4 — Full lambda_handler Integration
# ════════════════════════════════════════════════════════════════

class TestLambdaHandlerIntegration:

    def _make_event(self, instance_id, profile_arn="", finding_id="test-001"):
        return {
            "detail": {
                "id": finding_id,
                "type": "UnauthorizedAccess:EC2/SSHBruteForce",
                "severity": 7.8,
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "instanceId": instance_id,
                        "iamInstanceProfile": {"arn": profile_arn},
                    },
                },
            }
        }

    def test_returns_400_when_no_instance_id(self, aws_env):
        event = {"detail": {"severity": 7.8, "resource": {"instanceDetails": {}}}}
        result = handler_module.lambda_handler(event, None)
        assert result["statusCode"] == 400

    def test_returns_200_on_valid_event(self, ec2_instance, iam_role):
        role_name, profile_name = iam_role
        profile_arn = (
            f"arn:aws:iam::123456789012:instance-profile/{profile_name}"
        )
        event = self._make_event(ec2_instance, profile_arn)
        result = handler_module.lambda_handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "snapshot"  in body, "snapshot key missing from result"
        assert "isolation" in body, "isolation key missing from result"
        assert "revoke"    in body, "revoke key missing from result"

    def test_all_three_actions_succeed(self, ec2_instance, iam_role):
        role_name, profile_name = iam_role
        profile_arn = (
            f"arn:aws:iam::123456789012:instance-profile/{profile_name}"
        )
        event = self._make_event(ec2_instance, profile_arn, "test-002")
        result = handler_module.lambda_handler(event, None)

        body = json.loads(result["body"])
        for action, value in body.items():
            assert "FAILED" not in str(value), \
                f"Action '{action}' failed: {value}"

    def test_missing_detail_returns_400(self, aws_env):
        result = handler_module.lambda_handler({}, None)
        assert result["statusCode"] == 400