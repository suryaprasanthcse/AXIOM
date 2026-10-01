"""Collect proof-of-agent-connection evidence for the submission and render it to PNG.

Every exhibit is gathered live from AWS, the AXIOM ledger and git, saved as text
under submission/evidence/, and rendered to PNG with headless Microsoft Edge.
Account IDs and IP addresses are masked. Run from the project root:

    python scripts/collect_evidence.py
"""

import html
import json
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "submission" / "evidence"
ARENA = "https://oocyfygzrk.execute-api.us-west-2.amazonaws.com"
AGENT_PLAN = "1790870119809-1dacf9af"  # the agent's executed update (declared scope, UPDATE_COMPLETE)
AWS = r"C:\Program Files\Amazon\AWSCLIV2\aws.exe"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
ACCOUNT = "841535407298"


def mask(text: str) -> str:
    text = text.replace(ACCOUNT, f"{ACCOUNT[:4]}****{ACCOUNT[-4:]}")
    return re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "x.x.x.x", text)


def run(cmd: list[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    return (res.stdout + res.stderr).strip()


def exhibit_identity() -> str:
    lines = ["$ aws sts get-caller-identity --profile axiom          # the builder credentials Claude Code ran with",
             run([AWS, "sts", "get-caller-identity", "--profile", "axiom"]), "",
             "$ python agent/axiom_agent.py whoami                     # the coding agent's own identity",
             run([sys.executable, "agent/axiom_agent.py", "whoami"]), "",
             "$ aws cloudformation create-change-set ... --profile axiom-agent   # the agent cannot write directly",
             run([AWS, "cloudformation", "create-change-set", "--stack-name", "axiom-demo-orders",
                  "--change-set-name", "evidence-probe", "--template-body", "file://demo/orders-v1.json",
                  "--profile", "axiom-agent"])]
    return "\n".join(lines)


def cloudtrail_events(ct, name: str, since: datetime):
    pages = ct.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}], StartTime=since)
    for page in pages:
        for e in page["Events"]:
            yield json.loads(e["CloudTrailEvent"])


def exhibit_cloudtrail(record: dict) -> str:
    session = boto3.Session(profile_name="axiom", region_name="us-west-2")
    ct = session.client("cloudtrail")
    since = datetime.now(timezone.utc) - timedelta(days=2)
    session_name = f"axiom-{AGENT_PLAN}"
    out = [f"CloudTrail (us-west-2), cross-checked against AXIOM ledger plan {AGENT_PLAN}", ""]

    out.append("1) The coding agent's session: AssumeRole into axiom-agent-role")
    for e in cloudtrail_events(ct, "AssumeRole", since):
        rp = e.get("requestParameters") or {}
        if str(rp.get("roleArn", "")).endswith("role/axiom-agent-role"):
            out.append(f"   {e['eventTime']}  session={rp.get('roleSessionName')}  by={e['userIdentity'].get('arn')}")
            out.append(f"   userAgent={e.get('userAgent', '')[:110]}")
            break

    minted = None
    out += ["", "2) The broker mints the proof-scoped credential: AssumeRole into axiom-executor-role"]
    for e in cloudtrail_events(ct, "AssumeRole", since):
        rp = e.get("requestParameters") or {}
        if rp.get("roleSessionName") == session_name:
            minted = e
            tags = {t["key"]: t["value"] for t in rp.get("tags", [])}
            out.append(f"   {e['eventTime']}  by={e['userIdentity'].get('arn')}")
            out.append(f"   durationSeconds={rp.get('durationSeconds')}  tags={json.dumps(tags)}")
            out.append(f"   issued accessKeyId={(e.get('responseElements') or {}).get('credentials', {}).get('accessKeyId')}")
            break

    executed = None
    out += ["", "3) The agent uses it: ExecuteChangeSet"]
    for e in cloudtrail_events(ct, "ExecuteChangeSet", since):
        if session_name in e["userIdentity"].get("arn", ""):
            executed = e
            out.append(f"   {e['eventTime']}  by={e['userIdentity']['arn']}")
            out.append(f"   accessKeyId={e['userIdentity'].get('accessKeyId')}  "
                       f"changeSet={str((e.get('requestParameters') or {}).get('changeSetName', ''))[-60:]}  "
                       f"error={e.get('errorCode', 'none')}")
            break

    out += ["", "4) Off-plan calls with an AXIOM credential are denied (DeleteTable)"]
    for e in cloudtrail_events(ct, "DeleteTable", since):
        if "axiom-executor-role" in e["userIdentity"].get("arn", ""):
            out.append(f"   {e['eventTime']}  by={e['userIdentity']['arn']}  error={e.get('errorCode')}")
            break

    cred = record.get("credential") or {}
    tags = {t["key"]: t["value"] for t in ((minted or {}).get("requestParameters") or {}).get("tags", [])}
    checks = [
        ("ledger proof_hash == CloudTrail session tag axiom-proof", record.get("proof_hash") == tags.get("axiom-proof")),
        ("ledger access_key_id == key used for ExecuteChangeSet",
         bool(executed) and cred.get("access_key_id") == executed["userIdentity"].get("accessKeyId")),
    ]
    out += ["", "Cross-check"] + [f"   {'MATCH' if ok else 'MISMATCH'}  {label}" for label, ok in checks]
    return "\n".join(out)


def exhibit_ledger(record: dict) -> str:
    keep = {k: record.get(k) for k in ("plan_id", "created_at", "source", "caller", "stack", "intent", "scope",
                                       "verdict", "proof_hash", "credential")}
    return f"$ curl {ARENA}/api/arena/plan/{AGENT_PLAN}\n" + json.dumps(keep, indent=2)


def exhibit_git() -> str:
    return "$ git log --format=...\n" + run(["git", "log", "--format=commit %h  %ad%nAuthor: %an%n%n%B", "--date=iso"])


def exhibit_mcp() -> str | None:
    """Agent calls made through the AWS MCP Server (Agent Toolkit), if any exist yet."""
    ct = boto3.Session(profile_name="axiom", region_name="us-west-2").client("cloudtrail")
    since = datetime.now(timezone.utc) - timedelta(days=2)
    pages = ct.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "true"}], StartTime=since)
    rows = []
    for page in pages:
        for e in page["Events"]:
            ev = json.loads(e["CloudTrailEvent"])
            if ev.get("userIdentity", {}).get("invokedBy") == "aws-mcp.amazonaws.com":
                rows.append(f"   {ev['eventTime']}  {ev['eventSource']}:{ev['eventName']}  "
                            f"by={ev['userIdentity'].get('arn')}  invokedBy={ev['userIdentity']['invokedBy']}")
        if len(rows) >= 12:
            break
    if not rows:
        return None
    return "CloudTrail events made by the coding agent through the AWS MCP Server (Agent Toolkit)\n\n" + "\n".join(rows)


def render(name: str, title: str, body: str) -> Path:
    txt = OUT / f"{name}.txt"
    txt.write_text(body + "\n", encoding="utf-8")
    page = OUT / f"{name}.html"
    page.write_text(f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;background:#0c0c0c;color:#efede6;font:15px/1.5 Consolas,Menlo,monospace}}
.bar{{background:#efede6;color:#0c0c0c;font-weight:700;padding:10px 18px;letter-spacing:.06em}}
pre{{margin:0;padding:18px;white-space:pre-wrap;word-break:break-all}}
.m{{color:#2ecc71}}.x{{color:#ff4136}}</style>
<div class="bar">AXIOM / ZERO TO SHIPPED / {html.escape(title)}</div>
<pre>{html.escape(body).replace("MATCH ", '<span class="m">MATCH</span> ').replace("MISMATCH", '<span class="x">MISMATCH</span>')}</pre>""",
                    encoding="utf-8")
    png = OUT / f"{name}.png"
    height = 90 + 23 * sum(1 + len(line) // 125 for line in body.splitlines())
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    f"--user-data-dir={OUT / '.edge-profile'}", f"--window-size=1280,{height}",
                    f"--screenshot={png}", page.as_uri()], capture_output=True, timeout=60)
    page.unlink()
    return png


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    record = json.load(urllib.request.urlopen(f"{ARENA}/api/arena/plan/{AGENT_PLAN}", timeout=30))["record"]
    exhibits = [
        ("1-agent-identity", "CODING AGENT IDENTITY ON AWS", exhibit_identity()),
        ("2-cloudtrail-proof-chain", "CLOUDTRAIL: AGENT -> PROOF -> CREDENTIAL -> CHANGE", exhibit_cloudtrail(record)),
        ("3-ledger-agent-session", "AXIOM LEDGER: THE CODING AGENT'S OWN SESSION", exhibit_ledger(record)),
        ("4-git-coauthor", "GIT HISTORY: CLAUDE CODE AS CO-AUTHOR", exhibit_git()),
    ]
    mcp = exhibit_mcp()
    if mcp:
        exhibits.append(("5-aws-mcp-server", "AWS MCP SERVER (AGENT TOOLKIT) CALLS IN CLOUDTRAIL", mcp))
    else:
        print("no AWS MCP Server events in CloudTrail yet: exhibit 5 skipped")
    for name, title, body in exhibits:
        png = render(name, title, mask(body))
        print(f"{png.name}: {'ok' if png.exists() else 'RENDER FAILED'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
