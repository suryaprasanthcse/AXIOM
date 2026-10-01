"""IAM Access Analyzer checks on the policies a change set would deploy.

Access Analyzer's custom policy checks use automated reasoning (Zelkova) to
prove whether a policy can grant public access, new access, or specific
privileged actions. CloudFormation templates hold policies with intrinsic
functions, so they are resolved to concrete ARNs before checking.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from axioms import BLOCK, WARN, Finding, identity_policies

# Resource type -> (path to the policy inside Properties, Access Analyzer resourceType)
RESOURCE_POLICIES = {
    "AWS::S3::BucketPolicy": (("PolicyDocument",), "AWS::S3::Bucket"),
    "AWS::SQS::QueuePolicy": (("PolicyDocument",), "AWS::SQS::Queue"),
    "AWS::SNS::TopicPolicy": (("PolicyDocument",), "AWS::SNS::Topic"),
    "AWS::KMS::Key": (("KeyPolicy",), "AWS::KMS::Key"),
    "AWS::IAM::Role": (("AssumeRolePolicyDocument",), "AWS::IAM::AssumeRolePolicyDocument"),
    "AWS::SecretsManager::ResourcePolicy": (("ResourcePolicy",), "AWS::SecretsManager::Secret"),
    "AWS::DynamoDB::Table": (("ResourcePolicy", "PolicyDocument"), "AWS::DynamoDB::Table"),
}

# Actions that let a principal escalate privilege or erase evidence.
PRIVILEGED_ACTIONS = [
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "kms:ScheduleKeyDeletion",
    "kms:PutKeyPolicy",
    "s3:PutBucketPolicy",
    "organizations:LeaveOrganization",
]

_client = None


def _aa():
    global _client
    if _client is None:
        _client = boto3.client("accessanalyzer", config=Config(retries={"total_max_attempts": 3, "mode": "standard"}))
    return _client


def check(before: dict, after: dict, account: str, region: str,
          allow_paid_calls: Callable[[int], bool] = lambda n: True) -> tuple[list[Finding], list[dict]]:
    """Return (findings, check_log) for every resource and identity policy in `after`.

    Custom policy checks are billed per call. `allow_paid_calls(n)` is asked once
    for the whole batch; if it declines, deterministic fallbacks run instead.
    """
    before_ctx = Resolver(before, account, region)
    after_ctx = Resolver(after, account, region)
    before_res = (before or {}).get("Resources") or {}
    after_res = (after or {}).get("Resources") or {}

    jobs = []
    for lid, r in after_res.items():
        spec = RESOURCE_POLICIES.get(r.get("Type"))
        if not spec:
            continue
        path, aa_type = spec
        doc = _dig(r.get("Properties") or {}, path)
        if not isinstance(doc, dict):
            continue
        new_doc = after_ctx.resolve(doc)
        old_raw = _dig((before_res.get(lid) or {}).get("Properties") or {}, path) if lid in before_res else None
        old_doc = before_ctx.resolve(old_raw) if isinstance(old_raw, dict) else None
        if old_doc == new_doc:
            continue  # unchanged policy: already in production, not introduced by this change
        jobs.append(("resource", lid, aa_type, new_doc, old_doc))

    before_identity = {lid: before_ctx.resolve(doc) for lid, doc in identity_policies(before_res)}
    for lid, doc in identity_policies(after_res):
        resolved = after_ctx.resolve(doc)
        if before_identity.get(lid) == resolved:
            continue  # unchanged policy: already in production, not introduced by this change
        jobs.append(("identity", lid, None, resolved, None))

    if not jobs:
        return [], []

    paid_calls = sum(2 if kind == "resource" and old is not None else 1 for kind, _, _, _, old in jobs)
    use_service = allow_paid_calls(paid_calls)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda job: _run(job, account, use_service), jobs))
    findings = [f for fs, _ in results for f in fs]
    log = [entry for _, entries in results for entry in entries]
    return findings, log


def _run(job, account: str, use_service: bool) -> tuple[list[Finding], list[dict]]:
    kind, lid, aa_type, new_doc, old_doc = job
    findings: list[Finding] = []
    log: list[dict] = []
    call = (lambda api, **kw: _call(api, lid, log, **kw)) if use_service else (lambda api, **kw: _skip(api, lid, log))
    if kind == "resource":
        res = call("CheckNoPublicAccess", policyDocument=json.dumps(new_doc), resourceType=aa_type)
        if res and res["result"] == "FAIL":
            findings.append(Finding("AX-11", BLOCK, "Policy grants public access",
                                    f"IAM Access Analyzer proved {lid}'s {aa_type} policy can be used by "
                                    f"anyone. {_reasons(res)}", lid, "access-analyzer"))
        elif res is None and _has_public_principal(new_doc):
            findings.append(Finding("AX-11", BLOCK, "Policy grants public access",
                                    f"{lid} allows Principal \"*\" without conditions. (Access Analyzer did "
                                    f"not run; deterministic fallback.)", lid, "axiom"))

        outsiders = _external_accounts(new_doc, account) - _external_accounts(old_doc or {}, account)
        expanded = None
        if old_doc is not None:
            expanded = call("CheckNoNewAccess", newPolicyDocument=json.dumps(new_doc),
                            existingPolicyDocument=json.dumps(old_doc), policyType="RESOURCE_POLICY")
        if outsiders:
            findings.append(Finding("AX-13", BLOCK, "Access granted to another AWS account",
                                    f"{lid} newly allows account(s) {', '.join(sorted(outsiders))}. "
                                    + (_reasons(expanded) if expanded and expanded["result"] == "FAIL" else ""),
                                    lid, "access-analyzer" if expanded else "axiom"))
        elif expanded and expanded["result"] == "FAIL":
            findings.append(Finding("AX-13", WARN, "Policy grants new access",
                                    f"IAM Access Analyzer found {lid}'s policy allows access the deployed "
                                    f"version did not. {_reasons(expanded)}", lid, "access-analyzer"))
    else:
        res = call("CheckAccessNotGranted", policyDocument=json.dumps(new_doc),
                   access=[{"actions": PRIVILEGED_ACTIONS}], policyType="IDENTITY_POLICY")
        if res and res["result"] == "FAIL":
            findings.append(Finding("AX-14", BLOCK, "Privilege-escalation permission granted",
                                    f"IAM Access Analyzer found {lid} can perform privileged IAM, KMS, "
                                    f"CloudTrail or bucket-policy actions. {_reasons(res)}", lid, "access-analyzer"))
        elif res is None and (granted := _privileged_actions_matched(new_doc)):
            findings.append(Finding("AX-14", BLOCK, "Privilege-escalation permission granted",
                                    f"{lid} allows {', '.join(granted[:4])}. (Access Analyzer did not run; "
                                    f"deterministic fallback.)", lid, "axiom"))
    return findings, log


def _skip(api: str, lid: str, log: list) -> None:
    log.append({"check": api, "resource": lid, "result": "SKIPPED",
                "message": "Arena daily budget for paid Access Analyzer checks reached; deterministic fallback used."})
    return None


def _privileged_actions_matched(doc: dict) -> list[str]:
    patterns = [str(a).lower() for st in _as_list(doc.get("Statement"))
                if isinstance(st, dict) and st.get("Effect") == "Allow" for a in _as_list(st.get("Action"))]
    return [a for a in PRIVILEGED_ACTIONS if any(fnmatch.fnmatchcase(a.lower(), p) for p in patterns)]


def _call(api: str, lid: str, log: list, **kwargs) -> dict | None:
    """Call one Access Analyzer check. Returns None (and logs the error) if the check cannot run."""
    method = {
        "CheckNoPublicAccess": "check_no_public_access",
        "CheckNoNewAccess": "check_no_new_access",
        "CheckAccessNotGranted": "check_access_not_granted",
    }[api]
    try:
        res = getattr(_aa(), method)(**kwargs)
    except (ClientError, BotoCoreError) as e:
        log.append({"check": api, "resource": lid, "result": "ERROR", "message": str(e)[:300]})
        return None
    log.append({
        "check": api,
        "resource": lid,
        "result": res["result"],
        "message": res.get("message", ""),
        "reasons": [r.get("description", "") for r in res.get("reasons", [])][:5],
    })
    return res


def _reasons(res: dict | None) -> str:
    if not res:
        return ""
    texts = [r.get("description", "") for r in res.get("reasons", []) if r.get("description")]
    return " ".join(texts[:2])


def _has_public_principal(doc: dict) -> bool:
    for st in _as_list(doc.get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow" and not st.get("Condition"):
            principal = st.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))):
                return True
    return False


def _external_accounts(doc: dict, account: str) -> set[str]:
    found = set()
    for st in _as_list((doc or {}).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        if not isinstance(principal, dict):
            continue
        for p in _as_list(principal.get("AWS")):
            m = re.match(r"^(?:arn:aws[\w-]*:(?:iam|sts)::)?(\d{12})(?::|$)", str(p))
            if m and m.group(1) != account:
                found.add(m.group(1))
    return found


class Resolver:
    """Resolves CloudFormation intrinsic functions to concrete, plausible values.

    Access Analyzer needs literal policy JSON. Same-stack references become
    ARNs in this account so ownership reasoning stays correct.
    """

    def __init__(self, template: dict, account: str, region: str):
        self.resources = (template or {}).get("Resources") or {}
        self.parameters = (template or {}).get("Parameters") or {}
        self.account = account
        self.region = region

    def resolve(self, value):
        if isinstance(value, dict):
            if len(value) == 1:
                (fn, arg), = value.items()
                if fn == "Ref":
                    return self.ref(arg)
                if fn == "Fn::GetAtt":
                    return self.get_att(arg)
                if fn == "Fn::Sub":
                    return self.sub(arg)
                if fn == "Fn::Join" and isinstance(arg, list) and len(arg) == 2:
                    parts = self.resolve(arg[1])
                    return str(arg[0]).join(str(p) for p in _as_list(parts))
                if fn == "Fn::Select" and isinstance(arg, list) and len(arg) == 2:
                    items = self.resolve(arg[1])
                    try:
                        return items[int(self.resolve(arg[0]))]
                    except (TypeError, ValueError, IndexError):
                        return f"arn:aws:iam::{self.account}:root"
                if fn.startswith("Fn::"):
                    return f"arn:aws:iam::{self.account}:root"
            out = {k: self.resolve(v) for k, v in value.items()}
            return {k: v for k, v in out.items() if v is not _NO_VALUE}
        if isinstance(value, list):
            return [v for v in (self.resolve(v) for v in value) if v is not _NO_VALUE]
        return value

    def ref(self, name: str):
        pseudo = {
            "AWS::AccountId": self.account,
            "AWS::Region": self.region,
            "AWS::Partition": "aws",
            "AWS::URLSuffix": "amazonaws.com",
            "AWS::StackName": "axiom-stack",
            "AWS::StackId": f"arn:aws:cloudformation:{self.region}:{self.account}:stack/axiom-stack/id",
        }
        if name == "AWS::NoValue":
            return _NO_VALUE
        if name in pseudo:
            return pseudo[name]
        if name in self.parameters:
            return (self.parameters[name] or {}).get("Default", f"param-{name}")
        rtype = (self.resources.get(name) or {}).get("Type", "")
        if rtype == "AWS::SQS::Queue":
            return f"https://sqs.{self.region}.amazonaws.com/{self.account}/{name}"
        if rtype in ("AWS::SNS::Topic",):
            return self.arn(name)
        if rtype == "AWS::S3::Bucket":
            return _bucket_name(name)
        return name

    def get_att(self, arg):
        lid, attr = (arg.split(".", 1) if isinstance(arg, str) else (arg[0], arg[1]))
        if attr == "Arn":
            return self.arn(lid)
        return f"{lid}-{attr}"

    def sub(self, arg):
        text, variables = (arg, {}) if isinstance(arg, str) else (arg[0], arg[1] or {})

        def replace(m):
            key = m.group(1)
            if key.startswith("!"):
                return "${" + key[1:] + "}"
            if key in variables:
                return str(self.resolve(variables[key]))
            if "." in key and key.split(".", 1)[0] in self.resources:
                return str(self.get_att(key))
            return str(self.ref(key))

        return re.sub(r"\$\{([^}]+)\}", replace, str(text))

    def arn(self, lid: str) -> str:
        rtype = (self.resources.get(lid) or {}).get("Type", "")
        a, r = self.account, self.region
        return {
            "AWS::S3::Bucket": f"arn:aws:s3:::{_bucket_name(lid)}",
            "AWS::SQS::Queue": f"arn:aws:sqs:{r}:{a}:{lid}",
            "AWS::SNS::Topic": f"arn:aws:sns:{r}:{a}:{lid}",
            "AWS::DynamoDB::Table": f"arn:aws:dynamodb:{r}:{a}:table/{lid}",
            "AWS::IAM::Role": f"arn:aws:iam::{a}:role/{lid}",
            "AWS::IAM::User": f"arn:aws:iam::{a}:user/{lid}",
            "AWS::Lambda::Function": f"arn:aws:lambda:{r}:{a}:function:{lid}",
            "AWS::KMS::Key": f"arn:aws:kms:{r}:{a}:key/00000000-0000-0000-0000-000000000000",
            "AWS::SecretsManager::Secret": f"arn:aws:secretsmanager:{r}:{a}:secret:{lid}-AbCdEf",
        }.get(rtype, f"arn:aws:{_service(rtype)}:{r}:{a}:{lid}")


class _NoValue:
    pass


_NO_VALUE = _NoValue()


def _bucket_name(lid: str) -> str:
    return ("axiom-" + re.sub(r"[^a-z0-9-]", "-", lid.lower()))[:63]


def _service(rtype: str) -> str:
    parts = rtype.split("::")
    return parts[1].lower() if len(parts) > 1 else "unknown"


def _dig(obj, path: tuple):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
