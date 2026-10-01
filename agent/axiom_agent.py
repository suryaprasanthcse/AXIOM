"""AXIOM agent client: what an AI coding agent runs instead of `cdk deploy`.

    plan     submit a template and its intent; on ALLOW, store the 15-minute credential
    execute  run the approved change set with that credential
    try      run any AWS CLI command with that credential, to show it can do nothing else
    whoami   show which identity the agent is using

The agent signs requests with its own view-only role (profile `axiom-agent`).
Minted credentials are kept in .axiom/sessions/ and never printed.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
SESSIONS = ROOT / ".axiom" / "sessions"
OUTPUT_FILES = (ROOT / ".axiom-outputs.json", ROOT / "axiom-outputs.json")
REGION = "us-west-2"


class AxiomError(Exception):
    pass


def plan_endpoint() -> str:
    if os.environ.get("AXIOM_AGENT_URL"):
        return os.environ["AXIOM_AGENT_URL"]
    outputs = next((p for p in OUTPUT_FILES if p.exists()), None)
    if outputs is None:
        raise AxiomError("Stack outputs file not found. Deploy the core stack with --outputs-file first.")
    for stack_outputs in json.loads(outputs.read_text()).values():
        if "AgentPlanEndpoint" in stack_outputs:
            return stack_outputs["AgentPlanEndpoint"]
    raise AxiomError("AgentPlanEndpoint missing from stack outputs.")


def plan(stack: str, template_path: str, intent: str, scope: list[str], profile: str) -> int:
    session = boto3.Session(profile_name=profile, region_name=REGION)
    print(f"agent identity: {session.client('sts').get_caller_identity()['Arn']}")
    body = json.dumps({
        "stack_name": stack,
        "intent": intent,
        "scope": [s.strip() for entry in scope for s in entry.split(",") if s.strip()],
        "template": json.loads(Path(template_path).read_text()),
    }).encode()
    url = plan_endpoint()
    signed = AWSRequest(method="POST", url=url, data=body, headers={"content-type": "application/json"})
    SigV4Auth(session.get_credentials().get_frozen_credentials(), "execute-api", REGION).add_auth(signed)
    request = urllib.request.Request(url, data=body, headers=dict(signed.headers.items()), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise AxiomError(f"AXIOM refused the request (HTTP {e.code}): {e.read().decode()[:500]}")

    record = data["record"]
    print_record(record)
    if "credentials" in data:
        SESSIONS.mkdir(parents=True, exist_ok=True)
        saved = {
            "plan_id": record["plan_id"],
            "stack_id": record["stack_id"],
            "change_set_arn": record["change_set"]["arn"],
            "change_set_type": record["change_set"]["type"],
            "proof_hash": record["proof_hash"],
            "credentials": data["credentials"],
        }
        (SESSIONS / f"{record['plan_id']}.json").write_text(json.dumps(saved, indent=2))
        (SESSIONS / "latest").write_text(record["plan_id"])
        print(f"\nproof-scoped credential stored for plan {record['plan_id']}"
              f" (expires {data['credentials']['Expiration']}).")
        print("next: python agent/axiom_agent.py execute")
    return 0 if record["verdict"] == "ALLOW" else 2


def execute(plan_id: str | None) -> int:
    saved = load_session(plan_id)
    cfn = minted_session(saved).client("cloudformation")
    print(f"executing change set {saved['change_set_arn']}")
    cfn.execute_change_set(ChangeSetName=saved["change_set_arn"])
    waiter = "stack_create_complete" if saved["change_set_type"] == "CREATE" else "stack_update_complete"
    cfn.get_waiter(waiter).wait(StackName=saved["stack_id"], WaiterConfig={"Delay": 5, "MaxAttempts": 120})
    status = cfn.describe_stacks(StackName=saved["stack_id"])["Stacks"][0]["StackStatus"]
    print(f"stack status: {status}")
    return 0


def try_cli(plan_id: str | None, command: list[str]) -> int:
    saved = load_session(plan_id)
    aws = shutil.which("aws") or r"C:\Program Files\Amazon\AWSCLIV2\aws.exe"
    creds = saved["credentials"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update({
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
        "AWS_REGION": REGION,
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    })
    print(f"running with plan {saved['plan_id']} credential: aws {' '.join(command)}")
    return subprocess.run([aws, *command], env=env).returncode


def whoami(profile: str) -> int:
    print(boto3.Session(profile_name=profile, region_name=REGION).client("sts").get_caller_identity()["Arn"])
    return 0


def load_session(plan_id: str | None) -> dict:
    if not plan_id:
        latest = SESSIONS / "latest"
        if not latest.exists():
            raise AxiomError("No minted credential yet. Run `plan` first.")
        plan_id = latest.read_text().strip()
    path = SESSIONS / f"{plan_id}.json"
    if not path.exists():
        raise AxiomError(f"No stored credential for plan {plan_id}.")
    return json.loads(path.read_text())


def minted_session(saved: dict) -> boto3.Session:
    creds = saved["credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=REGION,
    )


def print_record(r: dict) -> None:
    a = r.get("assessment") or {}
    print(f"\n=== {r['verdict']} === plan {r['plan_id']} on {r['stack']} ({r['timing_ms']} ms)")
    print(a.get("text") or r.get("error") or "")
    print(f"proof hash: {r.get('proof_hash')}")
    if r.get("credential"):
        c = r["credential"]
        print(f"  credential: {c['access_key_id']} on {c['role_arn']}, expires {c['expiration']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="ask AXIOM for a proof")
    p.add_argument("--stack", required=True, help="stack name, must start with axiom-demo-")
    p.add_argument("--template", required=True, help="CloudFormation JSON template (e.g. cdk.out/X.template.json)")
    p.add_argument("--intent", required=True, help="what this change is for, in one sentence")
    p.add_argument("--scope", required=True, action="append",
                   help="resources this change may touch: LogicalId[:add|modify|remove|*] (repeat or comma-separate)")
    p.add_argument("--profile", default="axiom-agent")
    e = sub.add_parser("execute", help="execute the approved change set")
    e.add_argument("--plan")
    t = sub.add_parser("try", help="run an AWS CLI command with the minted credential")
    t.add_argument("--plan")
    t.add_argument("command", nargs=argparse.REMAINDER, help="AWS CLI arguments after --")
    w = sub.add_parser("whoami", help="show the agent identity")
    w.add_argument("--profile", default="axiom-agent")
    args = parser.parse_args()

    try:
        if args.cmd == "plan":
            return plan(args.stack, args.template, args.intent, args.scope, args.profile)
        if args.cmd == "execute":
            return execute(args.plan)
        if args.cmd == "try":
            return try_cli(args.plan, [c for c in args.command if c != "--"])
        return whoami(args.profile)
    except (AxiomError, ClientError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
