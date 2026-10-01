"""AXIOM broker: the only principal that can mint execution credentials.

Flow for an agent request:
  1. The agent (axiom-agent-role, view-only) submits a template and its intent.
  2. The broker creates a CloudFormation change set with the CFN service role,
     so CloudFormation itself computes the diff.
  3. Axioms and IAM Access Analyzer decide the verdict. A deterministic report
     restates exactly why. No model is anywhere in this path.
  4. On ALLOW, the broker assumes axiom-executor-role with a session policy that
     permits ExecuteChangeSet on exactly that change set, for 15 minutes, and
     tags the session with the plan ID and proof hash.
Arena requests run the same pipeline but never mint and never execute. Identical
arena submissions are served from a 24-hour cache, and paid Access Analyzer calls
from the public arena are capped per day so the account cannot be drained.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, WaiterError

import analyzer
import axioms
import explain
import ledger

log = logging.getLogger()
log.setLevel(logging.INFO)

ACCOUNT = os.environ["ACCOUNT_ID"]
REGION = os.environ["AWS_REGION"]
CFN_ROLE_ARN = os.environ["CFN_ROLE_ARN"]
EXECUTOR_ROLE_ARN = os.environ["EXECUTOR_ROLE_ARN"]
AGENT_ROLE_NAME = os.environ["AGENT_ROLE_NAME"]
ARENA_STACK = os.environ["ARENA_STACK"]
ARENA_DAILY_CHECKS = int(os.environ.get("ARENA_DAILY_CHECKS", "250"))
DEMO_STACK_PATTERN = re.compile(r"^axiom-demo-[a-z0-9-]{1,40}$")
MAX_TEMPLATE_BYTES = 51200
SESSION_SECONDS = 900
NO_CHANGES = ("didn't contain changes", "No updates are to be performed")
# Bump when evaluation output changes so the arena cache stops serving older records.
EVALUATOR_VERSION = 3

_config = Config(retries={"total_max_attempts": 3, "mode": "standard"})
cfn = boto3.client("cloudformation", config=_config)
sts = boto3.client("sts", config=_config)
ddb = boto3.client("dynamodb", config=_config)


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def handler(event, context):
    route = event.get("routeKey", "")
    try:
        if route == "POST /agent/plan":
            return _json(200, _agent_plan(event))
        if route == "POST /api/arena/review":
            return _json(200, _arena_review(event))
        if route == "GET /api/arena/baseline":
            return _json(200, _baseline())
        if route == "GET /api/arena/ledger":
            return _json(200, {"records": ledger.recent()})
        if route == "GET /api/arena/plan/{plan_id}":
            record = ledger.get((event.get("pathParameters") or {}).get("plan_id", ""))
            return _json(200, {"record": record}) if record else _json(404, {"error": "unknown plan"})
        return _json(404, {"error": "not found"})
    except RequestError as e:
        return _json(e.status, {"error": str(e)})
    except ClientError as e:
        log.exception("AWS call failed")
        return _json(502, {"error": f"AWS rejected a call: {e.response['Error'].get('Code')}: "
                                   f"{e.response['Error'].get('Message', '')[:300]}"})


# --- routes ------------------------------------------------------------------

def _agent_plan(event) -> dict:
    caller = (((event.get("requestContext") or {}).get("authorizer") or {}).get("iam") or {}).get("userArn", "")
    if not caller.startswith(f"arn:aws:sts::{ACCOUNT}:assumed-role/{AGENT_ROLE_NAME}/"):
        raise RequestError(403, "Only sessions of the AXIOM agent role may request execution credentials.")
    body = _body(event)
    stack = str(body.get("stack_name", ""))
    intent = str(body.get("intent", "")).strip()
    if not DEMO_STACK_PATTERN.match(stack):
        raise RequestError(400, "stack_name must match axiom-demo-<name> (lowercase, digits, hyphens).")
    if not 3 <= len(intent) <= 500:
        raise RequestError(400, "intent is required (3-500 characters): say what this change is for.")
    scope = _scope(body.get("scope"), required=True)
    record, credentials = evaluate(stack, body.get("template"), intent, scope, "agent", caller)
    response = {"record": record}
    if credentials:
        response["credentials"] = credentials
    return response


def _arena_review(event) -> dict:
    body = _body(event)
    intent = str(body.get("intent", "")).strip()[:500]
    scope = _scope(body.get("scope"), required=False)
    record, _ = evaluate(ARENA_STACK, body.get("template"), intent, scope, "arena", "public-arena")
    return {"record": record}


def _scope(value, required: bool) -> list[str] | None:
    if value in (None, [], "") and not required:
        return None
    if value in (None, [], ""):
        raise RequestError(400, "scope is required: list the resources this change may touch, "
                                "e.g. [\"OrdersDLQ:add\", \"OrdersQueue:modify\"].")
    try:
        axioms.parse_scope(value)
    except ValueError as e:
        raise RequestError(400, str(e))
    return [str(v).strip() for v in value]


_baseline_cache: dict = {}


def _baseline() -> dict:
    if _baseline_cache.get("expires", 0) < time.time():
        body = cfn.get_template(StackName=ARENA_STACK, TemplateStage="Original")["TemplateBody"]
        _baseline_cache.update(template=_as_template(body), expires=time.time() + 60)
    return {"stack": ARENA_STACK, "template": _baseline_cache["template"]}


# --- the pipeline -------------------------------------------------------------

def evaluate(stack: str, template_in, intent: str, scope: list[str] | None, source: str,
             caller: str) -> tuple[dict, dict | None]:
    started = time.time()
    template = _parse_template(template_in)
    body_text = json.dumps(template, separators=(",", ":"))
    if len(body_text.encode()) > MAX_TEMPLATE_BYTES:
        raise RequestError(413, f"Template is larger than {MAX_TEMPLATE_BYTES} bytes.")

    cache_key = ledger.canonical_hash({"v": EVALUATOR_VERSION, "stack": stack, "template": template,
                                       "intent": intent, "scope": scope})
    if source == "arena":
        cached = ledger.cached_arena(cache_key)
        if cached:
            return {**cached, "cached": True}, None

    plan_id = f"{int(started * 1000):013d}-{secrets.token_hex(4)}"
    cs_name = f"axiom-{plan_id}"
    existing = _stack_status(stack)
    cs_type = "UPDATE" if existing and existing != "REVIEW_IN_PROGRESS" else "CREATE"
    before = _as_template(cfn.get_template(StackName=stack, TemplateStage="Original")["TemplateBody"]) \
        if cs_type == "UPDATE" else {}

    # The authenticated agent path always gets the paid checks; the public arena is budgeted.
    budget = (lambda n: True) if source == "agent" else (lambda n: ledger.take_check_budget(n, ARENA_DAILY_CHECKS))

    # Access Analyzer only needs the templates, so it runs while CloudFormation computes the diff.
    with ThreadPoolExecutor(max_workers=1) as pool:
        aa_future = pool.submit(analyzer.check, before, template, ACCOUNT, REGION, budget)
        created = cfn.create_change_set(
            StackName=stack,
            ChangeSetName=cs_name,
            ChangeSetType=cs_type,
            TemplateBody=body_text,
            RoleARN=CFN_ROLE_ARN,
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            # No Tags here: stack tags propagate to every resource, which would add an
            # unrelated tag change to every plan. The plan ID lives in the change set name.
            Description=f"AXIOM plan {plan_id} ({source})",
        )
        cs_arn, stack_id = created["Id"], created["StackId"]
        status, reason, changes = _wait_for_change_set(cs_arn)
        aa_findings, aa_checks = aa_future.result()

    base = {
        "plan_id": plan_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "source": source,
        "caller": caller,
        "stack": stack,
        "stack_id": stack_id,
        "change_set": {"name": cs_name, "arn": cs_arn, "type": cs_type},
        "intent": intent,
        "scope": scope,
        "template_sha256": ledger.canonical_hash(template),
    }

    if status != "CREATE_COMPLETE":
        _discard(cs_arn, stack_id, cs_type)
        no_op = any(marker in reason for marker in NO_CHANGES)
        record = {**base, "verdict": "NOOP" if no_op else "ERROR", "error": reason[:500], "findings": [],
                  "checks": aa_checks, "changes": [], "assessment": None, "session_policy": None,
                  "timing_ms": int((time.time() - started) * 1000)}
        record["proof_hash"] = ledger.canonical_hash(record)
        ledger.put(record)
        return record, None

    raw = axioms.evaluate(changes, before, template) + axioms.scope_findings(changes, scope) + aa_findings
    findings = [f.to_dict() for f in axioms.sort_findings(raw)]
    summary = _summarize(changes)
    data_at_risk = _data_at_risk(changes)
    verdict = "BLOCK" if any(f["severity"] == axioms.BLOCK for f in findings) else "ALLOW"
    assessment = explain.report(verdict, intent, scope, summary, findings, aa_checks, data_at_risk)

    session_policy = _session_policy(stack_id, cs_arn, cs_name)
    record = {
        **base,
        "verdict": verdict,
        "changes": summary,
        "findings": findings,
        "checks": aa_checks,
        "data_at_risk": data_at_risk,
        "assessment": assessment,
        "session_policy": session_policy,
        "would_mint": verdict == "ALLOW",
        "timing_ms": int((time.time() - started) * 1000),
    }
    record["proof_hash"] = ledger.canonical_hash(record)

    credentials = None
    if source == "agent" and verdict == "ALLOW":
        credentials = _mint(plan_id, record["proof_hash"], session_policy)
        record["credential"] = {
            "access_key_id": credentials["AccessKeyId"],
            "expiration": credentials["Expiration"],
            "role_arn": EXECUTOR_ROLE_ARN,
            "duration_seconds": SESSION_SECONDS,
            "session_tags": {"axiom-plan": plan_id, "axiom-proof": record["proof_hash"]},
        }
    else:
        _discard(cs_arn, stack_id, cs_type)
    ledger.put(record)
    if source == "arena":
        ledger.remember_arena(cache_key, plan_id)
    return record, credentials


def _wait_for_change_set(cs_arn: str) -> tuple[str, str, list[dict]]:
    try:
        cfn.get_waiter("change_set_create_complete").wait(
            ChangeSetName=cs_arn, WaiterConfig={"Delay": 1, "MaxAttempts": 14})
    except WaiterError:
        pass  # FAILED or slow: the status below says which
    pages = cfn.get_paginator("describe_change_set").paginate(ChangeSetName=cs_arn, IncludePropertyValues=True)
    status, reason, changes = "UNKNOWN", "", []
    for page in pages:
        status, reason = page.get("Status", status), page.get("StatusReason", reason) or reason
        changes += [c["ResourceChange"] for c in page.get("Changes", []) if c.get("Type") == "Resource"]
    return status, reason, changes


def _session_policy(stack_id: str, cs_arn: str, cs_name: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExecuteExactlyThisChangeSet",
                "Effect": "Allow",
                "Action": "cloudformation:ExecuteChangeSet",
                "Resource": [stack_id, cs_arn],
                "Condition": {"StringEquals": {"cloudformation:ChangeSetName": cs_name}},
            },
            {
                "Sid": "ObserveThisStackOnly",
                "Effect": "Allow",
                "Action": ["cloudformation:DescribeStacks", "cloudformation:DescribeStackEvents",
                           "cloudformation:DescribeChangeSet"],
                "Resource": [stack_id, cs_arn],
            },
        ],
    }


def _mint(plan_id: str, proof_hash: str, session_policy: dict) -> dict:
    creds = sts.assume_role(
        RoleArn=EXECUTOR_ROLE_ARN,
        RoleSessionName=f"axiom-{plan_id}",
        DurationSeconds=SESSION_SECONDS,
        Policy=json.dumps(session_policy, separators=(",", ":")),
        Tags=[{"Key": "axiom-plan", "Value": plan_id}, {"Key": "axiom-proof", "Value": proof_hash}],
    )["Credentials"]
    return {
        "AccessKeyId": creds["AccessKeyId"],
        "SecretAccessKey": creds["SecretAccessKey"],
        "SessionToken": creds["SessionToken"],
        "Expiration": creds["Expiration"].isoformat(),
    }


def _discard(cs_arn: str, stack_id: str, cs_type: str) -> None:
    """Best-effort cleanup of a change set that will never run. Failure here must not lose the verdict."""
    try:
        cfn.delete_change_set(ChangeSetName=cs_arn)
        if cs_type == "CREATE":
            cfn.delete_stack(StackName=stack_id)  # empty stack left in REVIEW_IN_PROGRESS
    except ClientError:
        log.warning("cleanup failed for %s", cs_arn, exc_info=True)


def _summarize(changes: list[dict]) -> list[dict]:
    out = []
    for c in changes:
        props = sorted({
            d["Target"].get("Name") or d["Target"].get("Attribute", "")
            for d in c.get("Details", []) if d.get("Target")
        } - {""})
        out.append({
            "action": c.get("Action"),
            "logical_id": c.get("LogicalResourceId"),
            "type": c.get("ResourceType"),
            "physical_id": c.get("PhysicalResourceId"),
            "replacement": c.get("Replacement"),
            "properties": props,
        })
    return out


def _data_at_risk(changes: list[dict]) -> list[dict]:
    out = []
    for c in changes:
        destructive = c.get("Action") == "Remove" or (
            c.get("Action") == "Modify" and c.get("Replacement") in ("True", "Conditional"))
        if c.get("ResourceType") != "AWS::DynamoDB::Table" or not destructive or not c.get("PhysicalResourceId"):
            continue
        try:
            table = ddb.describe_table(TableName=c["PhysicalResourceId"])["Table"]
        except ddb.exceptions.ResourceNotFoundException:
            continue
        out.append({
            "resource": c["LogicalResourceId"],
            "table": c["PhysicalResourceId"],
            "item_count": table.get("ItemCount", 0),
            "size_bytes": table.get("TableSizeBytes", 0),
            "note": "DynamoDB refreshes ItemCount about every six hours.",
        })
    return out


def _stack_status(stack: str) -> str | None:
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as e:
        if "does not exist" in e.response["Error"].get("Message", ""):
            return None
        raise


# --- request helpers ----------------------------------------------------------

def _body(event) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise RequestError(400, "Body must be JSON.")
    if not isinstance(data, dict):
        raise RequestError(400, "Body must be a JSON object.")
    return data


def _parse_template(value) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as e:
            raise RequestError(400, f"Template is not valid JSON: {e.msg} (line {e.lineno}).")
    if not isinstance(value, dict) or not isinstance(value.get("Resources"), dict) or not value["Resources"]:
        raise RequestError(400, "Template must be a CloudFormation JSON object with a non-empty Resources map.")
    return value


def _as_template(body) -> dict:
    return json.loads(body) if isinstance(body, str) else json.loads(json.dumps(body))


def _json(status: int, payload: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(payload, default=str),
    }
