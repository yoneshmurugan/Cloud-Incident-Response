# Architecture Deep Dive

## System Design Decisions

### Why EventBridge over SNS or SQS?

| Concern | SNS | SQS | EventBridge |
|:---|:---|:---|:---|
| Content-based filtering | No | No | **Yes** |
| Native GuardDuty integration | No | No | **Yes** |
| Multiple targets from one rule | Via fan-out | No | **Yes** |
| Latency | Low | Medium (polling) | **Low (push)** |

EventBridge was chosen because it filters at the router layer — the Lambda is only invoked
on findings that actually match our criteria. With SNS, all findings would arrive at Lambda
and we'd filter in code, wasting invocations and adding complexity.

---

### Why Concurrent Execution?

Sequential containment would create attack windows between actions:

```
Sequential (naive):
t=0s  Snapshot starts
t=5s  Snapshot done → SG swap starts
t=10s SG swap done → IAM revoke starts
t=15s IAM revoke done

Window where attacker has live credentials + network: t=0 to t=10s (10 seconds)
```

```
Concurrent (this design):
t=0s  All three actions start simultaneously
t=5s  All three actions complete

Window: t=0 to t=5s (5 seconds)
```

The concurrent model also means a single action failure doesn't delay the others.
Partial containment is always better than sequential containment.

---

### Why Forensics Before Containment?

NIST SP 800-61 Computer Security Incident Handling Guide requires:

> "Evidence should be collected before containment activities are performed
> to preserve the original state of the evidence."

If we swapped the SG first and then snapshotted, the EBS volume would reflect
the post-isolation state rather than the active compromise state. In a legal
proceeding or compliance audit, this ordering error could invalidate the evidence.

The Lambda fires `trigger_ebs_snapshot` and `isolate_instance` **concurrently** —
but the snapshot API call is registered before the SG swap call in the executor
submission order, ensuring the snapshot request is in flight first.

---

### Why Inline Policy for IAM Revocation?

Two reasons:

1. **Auto-cleanup** — Inline policies are deleted automatically when the role is
   deleted. Managed policies require explicit detachment, creating orphan risk.

2. **Semantic clarity** — A managed policy represents a reusable permission grant.
   This inline policy is an emergency circuit breaker scoped to a single role.
   The 1:1 coupling is intentional.

**How it works:** STS credentials issued via IMDS remain structurally valid
(they haven't expired), but IAM evaluates policy on every API call. An explicit
`Deny` in any evaluated policy overrides any `Allow`. The attacker's credentials
are immediately useless without being rotated or deleted.

---

## IAM Policy Evaluation Order

When an EC2 instance calls an AWS API using its role credentials, IAM evaluates:

```
1. Explicit Deny in any policy?         → DENY (stop)
2. Service Control Policy (SCP) Allow?  → Continue
3. Resource-based policy Allow?         → Continue
4. Identity-based policy Allow?         → ALLOW
5. None of the above?                   → DENY (implicit)
```

Our inline `Deny *` policy fires at step 1 and terminates evaluation immediately.
This takes effect within milliseconds of `put_role_policy` completing.

---

## Idempotency Design

EventBridge guarantees **at-least-once** delivery. The same GuardDuty finding
can trigger Lambda more than once. Each action is idempotent:

### Snapshot Idempotency

```python
existing = ec2.describe_snapshots(
    Filters=[
        {'Name': 'volume-id',     'Values': [vol_id]},
        {'Name': 'tag:FindingId', 'Values': [finding_id]},
        {'Name': 'status',        'Values': ['pending', 'completed']},
    ],
    OwnerIds=['self'],
)
if existing:
    return existing[0]['SnapshotId']  # skip creation
```

### SG Isolation Idempotency

```python
current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
if current_sgs == [QUARANTINE_SG_ID]:
    return 'ALREADY_ISOLATED'
```

### IAM Revocation Idempotency

```python
try:
    iam.get_role_policy(RoleName=role_name, PolicyName=POLICY_NAME)
    return 'ALREADY_REVOKED'
except ClientError as e:
    if e.response['Error']['Code'] != 'NoSuchEntity':
        raise
# proceed with put_role_policy
```

---

## Threat Model

| Threat | Mitigation |
|:---|:---|
| Lambda role compromised | Tag-based Conditions limit blast radius to `Project:cloud-ir-pipeline` resources only |
| False positive quarantine | Severity >= 7.0 threshold + resourceType filter + tag-based IAM boundary |
| Duplicate Lambda invocations | Three-layer idempotency (tag query, SG comparison, get_role_policy) |
| Evidence tampering | Snapshot created before containment; tagged with FindingId |
| Attacker pivots before Lambda runs | Concurrent execution minimises window to ~5 seconds |
| GuardDuty disabled by attacker | IAM permissions for guardduty:DeleteDetector not granted to any application role |