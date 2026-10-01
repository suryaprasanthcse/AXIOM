"""Deterministic axioms evaluated against a CloudFormation change set.

The verdict comes from these rules (plus IAM Access Analyzer, see analyzer.py).
Nothing in this module calls a model.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

BLOCK = "BLOCK"
WARN = "WARN"
INFO = "INFO"
_RANK = {BLOCK: 0, WARN: 1, INFO: 2}

STATEFUL_TYPES = {
    "AWS::DynamoDB::Table",
    "AWS::DynamoDB::GlobalTable",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    "AWS::S3::Bucket",
    "AWS::EFS::FileSystem",
    "AWS::Cognito::UserPool",
    "AWS::KMS::Key",
    "AWS::SQS::Queue",
    "AWS::Kinesis::Stream",
    "AWS::OpenSearchService::Domain",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::Neptune::DBCluster",
    "AWS::DocDB::DBCluster",
    "AWS::SecretsManager::Secret",
    "AWS::Backup::BackupVault",
    "AWS::EC2::Volume",
}

# Types whose default DeletionPolicy is Snapshot rather than Delete.
_DEFAULT_SNAPSHOT = {"AWS::RDS::DBCluster", "AWS::RDS::DBInstance"}
_KEEPS_DATA = {"Retain", "RetainExceptOnCreate", "Snapshot"}

# Properties whose truthy value protects a resource from deletion or data loss.
PROTECTION_PROPERTIES = {
    "AWS::DynamoDB::Table": [
        ("DeletionProtectionEnabled",),
        ("PointInTimeRecoverySpecification", "PointInTimeRecoveryEnabled"),
    ],
    "AWS::RDS::DBInstance": [("DeletionProtection",)],
    "AWS::RDS::DBCluster": [("DeletionProtection",)],
    "AWS::Cognito::UserPool": [("DeletionProtection",)],
    "AWS::EC2::Instance": [("DisableApiTermination",)],
}

AUDIT_TYPES = {
    "AWS::CloudTrail::Trail",
    "AWS::Config::ConfigurationRecorder",
    "AWS::Config::DeliveryChannel",
    "AWS::GuardDuty::Detector",
}

ALWAYS_ON_COST_TYPES = {
    "AWS::EC2::NatGateway": "NAT gateways bill hourly plus per-GB processed",
    "AWS::OpenSearchService::Domain": "OpenSearch domains bill per instance-hour",
    "AWS::Redshift::Cluster": "Redshift clusters bill per node-hour",
    "AWS::RDS::DBCluster": "Aurora clusters bill per instance-hour",
    "AWS::RDS::DBInstance": "RDS instances bill per instance-hour",
    "AWS::SageMaker::Endpoint": "SageMaker endpoints bill per instance-hour",
    "AWS::MSK::Cluster": "MSK clusters bill per broker-hour",
    "AWS::EKS::Cluster": "EKS clusters bill per cluster-hour",
}
_EXPENSIVE_INSTANCE = re.compile(r"^(p\d|g\d|inf\d|trn\d|x\d|u-|dl\d)|\.metal|\.(1[6-9]|[2-9]\d)xlarge$")

AVAILABILITY_TYPES = {
    "AWS::Route53::RecordSet",
    "AWS::Route53::RecordSetGroup",
    "AWS::Route53::HostedZone",
    "AWS::CloudFront::Distribution",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ApiGateway::RestApi",
    "AWS::ApiGatewayV2::Api",
}

ADMIN_MANAGED_POLICIES = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess")

SECRET_VALUE = re.compile(
    r"(AKIA|ASIA)[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"
    r"|ghp_[0-9A-Za-z]{36}"
    r"|sk-[A-Za-z0-9_-]{20,}"
)
SECRET_NAME = re.compile(r"password|passwd|secret|token|api[_-]?key|private[_-]?key", re.IGNORECASE)


@dataclass
class Finding:
    axiom: str
    severity: str
    title: str
    detail: str
    resource: str = ""
    source: str = "axiom"

    def to_dict(self) -> dict:
        return asdict(self)


# --- AX-15: declared scope --------------------------------------------------
# The agent declares which resources a change may touch before it starts work:
#   "OrdersTable"        add or modify (never remove, unless declared)
#   "OrdersTable:modify" one action: add | modify | remove
#   "OrdersTable:*"      any action, including remove
_SCOPE_ENTRY = re.compile(r"^([A-Za-z0-9]{1,255})(?::(add|modify|remove|\*))?$")
_DEFAULT_ACTIONS = frozenset({"add", "modify"})
_ALL_ACTIONS = frozenset({"add", "modify", "remove", "import", "dynamic"})
MAX_SCOPE_ENTRIES = 50


def parse_scope(entries) -> dict[str, set[str]]:
    """Validate a declared scope. Raises ValueError with a message fit for the caller."""
    if not isinstance(entries, list) or not entries or len(entries) > MAX_SCOPE_ENTRIES:
        raise ValueError(f"scope must be a list of 1-{MAX_SCOPE_ENTRIES} entries like \"OrdersTable:modify\".")
    allowed: dict[str, set[str]] = {}
    for entry in entries:
        m = _SCOPE_ENTRY.match(str(entry).strip())
        if not m:
            raise ValueError(f"Invalid scope entry {entry!r}: use LogicalId, LogicalId:add|modify|remove, or LogicalId:*.")
        lid, action = m.group(1), m.group(2)
        actions = _ALL_ACTIONS if action == "*" else {action} if action else _DEFAULT_ACTIONS
        allowed.setdefault(lid, set()).update(actions)
    return allowed


def scope_findings(changes: list[dict], scope: list[str] | None) -> list[Finding]:
    """Block every change set entry the agent did not declare. No scope declared: rule not applied."""
    if scope is None:
        return []
    allowed = parse_scope(scope)
    out = []
    for c in changes:
        lid, rtype = c["LogicalResourceId"], c.get("ResourceType", "")
        action = str(c.get("Action", "")).lower()
        if action in allowed.get(lid, ()):
            continue
        if _knock_on_only(c, allowed):
            out.append(Finding("AX-15", INFO, "Knock-on change of a declared resource",
                               f"{lid} changes only because a resource in scope changed "
                               f"({_causes(c)}); implied by the declared scope.", lid))
            continue
        declared = ", ".join(sorted(allowed.get(lid, ()))) or "nothing"
        out.append(Finding("AX-15", BLOCK, "Change outside declared scope",
                           f"The change set would {action} {lid} ({rtype}), but the declared scope allows "
                           f"{declared} for it. Undeclared changes are how injected or accidental edits slip in.",
                           lid))
    changed = {c["LogicalResourceId"] for c in changes}
    for lid in sorted(set(allowed) - changed):
        out.append(Finding("AX-15", INFO, "Declared but not changed",
                           f"{lid} is in the declared scope but this change set does not touch it.", lid))
    return out


def _knock_on_only(change: dict, allowed: dict) -> bool:
    """True when every detail is caused by a declared resource and nothing is replaced."""
    details = change.get("Details") or []
    if not details or change.get("Replacement") == "True":
        return False
    for d in details:
        if d.get("ChangeSource") not in ("ResourceReference", "ResourceAttribute"):
            return False
        if (d.get("CausingEntity") or "").split(".")[0] not in allowed:
            return False
    return True


def _causes(change: dict) -> str:
    return ", ".join(sorted({(d.get("CausingEntity") or "?") for d in change.get("Details") or []}))


def verdict(findings: list[Finding]) -> str:
    return "BLOCK" if any(f.severity == BLOCK for f in findings) else "ALLOW"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_RANK.get(f.severity, 9), f.axiom, f.resource))


def evaluate(changes: list[dict], before: dict, after: dict) -> list[Finding]:
    """Run every axiom. `changes` are ResourceChange dicts from DescribeChangeSet."""
    before_res = _resources(before)
    after_res = _resources(after)
    findings: list[Finding] = []
    findings += _stateful_deletion(changes, before_res)
    findings += _stateful_replacement(changes, after_res)
    findings += _protection_removed(changes, before_res, after_res)
    findings += _open_ingress(before_res, after_res)
    findings += _iam_wildcards(before_res, after_res)
    findings += _audit_tampering(changes, after_res)
    findings += _plaintext_secrets(after, after_res)
    findings += _cost(changes, after_res)
    findings += _availability(changes)
    findings += _encryption_off(after_res)
    return findings


# --- AX-01 / AX-02: stateful deletion and the logical-ID rename footgun -----

def _stateful_deletion(changes: list[dict], before_res: dict) -> list[Finding]:
    added_by_type: dict[str, list[str]] = {}
    for c in changes:
        if c.get("Action") == "Add":
            added_by_type.setdefault(c.get("ResourceType", ""), []).append(c["LogicalResourceId"])

    out = []
    for c in changes:
        rtype = c.get("ResourceType", "")
        if c.get("Action") != "Remove" or rtype not in STATEFUL_TYPES:
            continue
        lid = c["LogicalResourceId"]
        physical = c.get("PhysicalResourceId") or "unknown"
        default = "Snapshot" if rtype in _DEFAULT_SNAPSHOT else "Delete"
        policy = before_res.get(lid, {}).get("DeletionPolicy", default)
        if policy in _KEEPS_DATA:
            out.append(Finding("AX-01", INFO, "Stateful resource removed but kept",
                               f"{rtype} {lid} ({physical}) leaves the stack with DeletionPolicy "
                               f"{policy}; AWS keeps the data.", lid))
            continue
        renamed_to = added_by_type.get(rtype, [])
        if renamed_to:
            new_id = renamed_to[0]
            out.append(Finding("AX-02", BLOCK, "Logical-ID rename destroys data",
                               f"{lid} is removed and {new_id} of the same type ({rtype}) is added. "
                               f"CloudFormation will delete {lid} ({physical}) and create an empty "
                               f"{new_id}; it does not move data between them.", lid))
        else:
            out.append(Finding("AX-01", BLOCK, "Stateful resource deleted",
                               f"{rtype} {lid} ({physical}) is removed with DeletionPolicy {policy}. "
                               f"Its data is destroyed.", lid))
    return out


# --- AX-03: stateful replacement -------------------------------------------

def _stateful_replacement(changes: list[dict], after_res: dict) -> list[Finding]:
    out = []
    for c in changes:
        rtype = c.get("ResourceType", "")
        replacement = c.get("Replacement")
        if c.get("Action") != "Modify" or rtype not in STATEFUL_TYPES:
            continue
        if replacement not in ("True", "Conditional"):
            continue
        lid = c["LogicalResourceId"]
        physical = c.get("PhysicalResourceId") or "unknown"
        props = sorted({
            d["Target"].get("Name") or d["Target"].get("Attribute", "")
            for d in c.get("Details", [])
            if d.get("Target", {}).get("RequiresRecreation") in ("Always", "Conditionally")
        } - {""})
        cause = ", ".join(props) if props else "a create-only property"
        urp = after_res.get(lid, {}).get("UpdateReplacePolicy", "Delete")
        if urp in _KEEPS_DATA:
            out.append(Finding("AX-03", WARN, "Stateful resource replaced, old copy kept",
                               f"Changing {cause} replaces {rtype} {lid}; UpdateReplacePolicy {urp} "
                               f"keeps the old {physical}, but the new resource starts empty.", lid))
        else:
            out.append(Finding("AX-03", BLOCK, "Stateful resource replaced",
                               f"Changing {cause} forces CloudFormation to create a new {rtype} and "
                               f"delete {lid} ({physical}) with its data. Replacement: {replacement}.",
                               lid))
    return out


# --- AX-04: protections removed --------------------------------------------

def _protection_removed(changes: list[dict], before_res: dict, after_res: dict) -> list[Finding]:
    modified = {c["LogicalResourceId"] for c in changes if c.get("Action") == "Modify"}
    out = []
    for lid in sorted(modified):
        b, a = before_res.get(lid), after_res.get(lid)
        if not b or not a:
            continue
        for path in PROTECTION_PROPERTIES.get(a.get("Type", ""), []):
            was = _truthy(_dig(b.get("Properties", {}), path))
            now = _truthy(_dig(a.get("Properties", {}), path))
            if was and not now:
                out.append(Finding("AX-04", BLOCK, "Protection turned off",
                                   f"{'.'.join(path)} on {lid} goes from enabled to disabled. "
                                   f"That removes the guard against deletion or data loss.", lid))
    return out


# --- AX-05: ingress open to the internet ------------------------------------

def _open_ingress(before_res: dict, after_res: dict) -> list[Finding]:
    before_rules = {_rule_key(lid, r) for lid, r in _ingress_rules(before_res)}
    out = []
    for lid, rule in _ingress_rules(after_res):
        if not _is_world(rule) or _web_only(rule):
            continue
        ports = _port_label(rule)
        if _rule_key(lid, rule) in before_rules:
            out.append(Finding("AX-05", WARN, "Pre-existing internet ingress",
                               f"{lid} already allows {ports} from anywhere. This change keeps it.", lid))
        else:
            out.append(Finding("AX-05", BLOCK, "Ingress opened to the internet",
                               f"{lid} would allow {ports} from {rule.get('CidrIp') or rule.get('CidrIpv6')}. "
                               f"Only TCP 80 and 443 may face the internet.", lid))
    return out


def _ingress_rules(resources: dict):
    for lid, r in resources.items():
        props = r.get("Properties") or {}
        if r.get("Type") == "AWS::EC2::SecurityGroup":
            for rule in props.get("SecurityGroupIngress") or []:
                if isinstance(rule, dict):
                    yield lid, rule
        elif r.get("Type") == "AWS::EC2::SecurityGroupIngress":
            yield lid, props


def _rule_key(lid: str, rule: dict) -> str:
    return lid + "|" + json.dumps(rule, sort_keys=True, default=str)


def _is_world(rule: dict) -> bool:
    return rule.get("CidrIp") == "0.0.0.0/0" or rule.get("CidrIpv6") == "::/0"


def _web_only(rule: dict) -> bool:
    if str(rule.get("IpProtocol")).lower() not in ("tcp", "6"):
        return False
    lo, hi = _as_int(rule.get("FromPort")), _as_int(rule.get("ToPort"))
    return lo is not None and lo == hi and lo in (80, 443)


def _port_label(rule: dict) -> str:
    proto = str(rule.get("IpProtocol"))
    if proto in ("-1", "all"):
        return "all traffic"
    lo, hi = rule.get("FromPort"), rule.get("ToPort")
    return f"{proto.upper()} {lo}" if lo == hi else f"{proto.upper()} {lo}-{hi}"


# --- AX-06: IAM wildcards and admin grants ----------------------------------

def _iam_wildcards(before_res: dict, after_res: dict) -> list[Finding]:
    before_keys = {k for k, _ in _risky_iam(before_res)}
    out = []
    for key, (lid, why) in _risky_iam(after_res):
        if key in before_keys:
            out.append(Finding("AX-06", WARN, "Pre-existing broad IAM grant", f"{lid}: {why} (unchanged).", lid))
        else:
            out.append(Finding("AX-06", BLOCK, "Broad IAM grant", f"{lid}: {why}.", lid))
    return out


def _risky_iam(resources: dict):
    for lid, doc in identity_policies(resources):
        for st in _statements(doc):
            if st.get("Effect") != "Allow":
                continue
            actions = [str(a) for a in _as_list(st.get("Action"))]
            key = lid + "|" + json.dumps(st, sort_keys=True, default=str)
            if any(a in ("*", "*:*") or a.lower() == "iam:*" for a in actions):
                yield key, (lid, f"allows {', '.join(actions)}")
            elif any(a.lower() == "iam:passrole" for a in actions) and "*" in _as_list(st.get("Resource")):
                yield key, (lid, "allows iam:PassRole on every role")
    for lid, r in resources.items():
        if r.get("Type") not in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"):
            continue
        for arn in _as_list((r.get("Properties") or {}).get("ManagedPolicyArns")):
            text = json.dumps(arn) if not isinstance(arn, str) else arn
            for name in ADMIN_MANAGED_POLICIES:
                if text.endswith(f"/{name}") or text.endswith(f'/{name}"'):
                    yield f"{lid}|{name}", (lid, f"attaches the {name} managed policy")


def identity_policies(resources: dict):
    """Yield (logical_id, policy_document) for every identity policy in a template."""
    for lid, r in resources.items():
        rtype, props = r.get("Type"), r.get("Properties") or {}
        if rtype in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy") and isinstance(props.get("PolicyDocument"), dict):
            yield lid, props["PolicyDocument"]
        elif rtype in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"):
            for p in props.get("Policies") or []:
                if isinstance(p, dict) and isinstance(p.get("PolicyDocument"), dict):
                    yield f"{lid}/{p.get('PolicyName', 'inline')}", p["PolicyDocument"]


# --- AX-07: audit tampering --------------------------------------------------

def _audit_tampering(changes: list[dict], after_res: dict) -> list[Finding]:
    out = []
    for c in changes:
        rtype, lid, action = c.get("ResourceType", ""), c["LogicalResourceId"], c.get("Action")
        if action == "Remove" and rtype in AUDIT_TYPES:
            out.append(Finding("AX-07", BLOCK, "Audit trail removed",
                               f"{rtype} {lid} is removed. Changes after this point would not be recorded.", lid))
        elif action == "Remove" and rtype == "AWS::Logs::LogGroup":
            out.append(Finding("AX-07", WARN, "Log group removed",
                               f"{lid} is removed and its log history with it.", lid))
        elif action == "Modify" and rtype == "AWS::CloudTrail::Trail":
            if not _truthy((after_res.get(lid, {}).get("Properties") or {}).get("IsLogging", True)):
                out.append(Finding("AX-07", BLOCK, "Audit trail stopped", f"{lid} sets IsLogging to false.", lid))
    return out


# --- AX-08: plaintext secrets ------------------------------------------------

def _plaintext_secrets(template: dict, after_res: dict) -> list[Finding]:
    out = []
    for lid, r in after_res.items():
        for path, value in _walk(r.get("Properties") or {}):
            if SECRET_VALUE.search(value):
                out.append(Finding("AX-08", BLOCK, "Credential in plaintext",
                                   f"{lid}.{path} contains what looks like a live credential. "
                                   f"Use Secrets Manager or a dynamic reference instead.", lid))
        for name, value in _env_vars(r):
            if SECRET_NAME.search(name) and len(value) >= 8 and not value.startswith("{{resolve:"):
                out.append(Finding("AX-08", BLOCK, "Secret in an environment variable",
                                   f"{lid} sets {name} to a literal value. Use Secrets Manager or a "
                                   f"dynamic reference instead.", lid))
    for name, p in (template.get("Parameters") or {}).items():
        default = p.get("Default") if isinstance(p, dict) else None
        if isinstance(default, str) and SECRET_NAME.search(name) and not p.get("NoEcho") and len(default) >= 8:
            out.append(Finding("AX-08", WARN, "Secret-looking parameter default",
                               f"Parameter {name} has a literal default and NoEcho is off.", name))
    return out


def _env_vars(resource: dict):
    props = resource.get("Properties") or {}
    variables = (props.get("Environment") or {}).get("Variables") if isinstance(props.get("Environment"), dict) else None
    if isinstance(variables, dict):
        for k, v in variables.items():
            if isinstance(v, str):
                yield k, v
    for container in props.get("ContainerDefinitions") or []:
        for env in (container or {}).get("Environment") or []:
            if isinstance(env, dict) and isinstance(env.get("Value"), str):
                yield str(env.get("Name", "")), env["Value"]


# --- AX-09: always-on cost ---------------------------------------------------

def _cost(changes: list[dict], after_res: dict) -> list[Finding]:
    out = []
    for c in changes:
        if c.get("Action") != "Add":
            continue
        rtype, lid = c.get("ResourceType", ""), c["LogicalResourceId"]
        props = after_res.get(lid, {}).get("Properties") or {}
        if rtype in ALWAYS_ON_COST_TYPES:
            out.append(Finding("AX-09", WARN, "Always-on cost added", f"{lid}: {ALWAYS_ON_COST_TYPES[rtype]}.", lid))
        elif rtype == "AWS::EC2::Instance" and _EXPENSIVE_INSTANCE.search(str(props.get("InstanceType", ""))):
            out.append(Finding("AX-09", WARN, "Expensive instance type",
                               f"{lid} launches {props.get('InstanceType')}.", lid))
        elif rtype == "AWS::DynamoDB::Table":
            pt = props.get("ProvisionedThroughput") or {}
            units = (_as_int(pt.get("ReadCapacityUnits")) or 0) + (_as_int(pt.get("WriteCapacityUnits")) or 0)
            if units > 1000:
                out.append(Finding("AX-09", WARN, "High provisioned capacity",
                                   f"{lid} provisions {units} capacity units around the clock.", lid))
    return out


# --- AX-10: availability -----------------------------------------------------

def _availability(changes: list[dict]) -> list[Finding]:
    return [
        Finding("AX-10", WARN, "Traffic entry point removed",
                f"{c['ResourceType']} {c['LogicalResourceId']} is removed; anything routed through it stops.",
                c["LogicalResourceId"])
        for c in changes
        if c.get("Action") == "Remove" and c.get("ResourceType") in AVAILABILITY_TYPES
    ]


# --- AX-12: encryption turned off -------------------------------------------

def _encryption_off(after_res: dict) -> list[Finding]:
    out = []
    for lid, r in after_res.items():
        rtype, props = r.get("Type"), r.get("Properties") or {}
        off = (
            (rtype in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster") and props.get("StorageEncrypted") is False)
            or (rtype == "AWS::EFS::FileSystem" and props.get("Encrypted") is False)
            or (rtype == "AWS::SQS::Queue" and props.get("SqsManagedSseEnabled") is False
                and not props.get("KmsMasterKeyId"))
        )
        if off:
            out.append(Finding("AX-12", WARN, "Encryption at rest disabled", f"{rtype} {lid} stores data unencrypted.", lid))
    return out


# --- helpers ---------------------------------------------------------------

def _resources(template: dict) -> dict:
    res = (template or {}).get("Resources") or {}
    return res if isinstance(res, dict) else {}


def _statements(doc: dict) -> list[dict]:
    return [s for s in _as_list((doc or {}).get("Statement")) if isinstance(s, dict)]


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dig(obj, path: tuple):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "active", "enabled")


def _walk(obj, prefix: str = ""):
    """Yield (dotted_path, string_value) for every literal string in a nested structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj
