"""Run every arena scenario against the live AXIOM URL and check verdicts.

Mirrors the scenarios in web/app.js. Each run tags the intent with a nonce so
the arena cache does not answer, then one repeat checks that the cache does.

    python scripts/arena_suite.py https://<api-id>.execute-api.us-west-2.amazonaws.com
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

AAA = "arn:aws:iam::444455556666:root"


def _table(t):
    return t["Resources"]["OrdersTable"]["Properties"]


def safe_index(t):
    _table(t)["AttributeDefinitions"].append({"AttributeName": "customerId", "AttributeType": "S"})
    _table(t)["GlobalSecondaryIndexes"] = [{
        "IndexName": "byCustomer",
        "KeySchema": [{"AttributeName": "customerId", "KeyType": "HASH"}],
        "Projection": {"ProjectionType": "ALL"},
    }]


def rekey(t):
    _table(t)["AttributeDefinitions"] = [{"AttributeName": "orderPk", "AttributeType": "S"}]
    _table(t)["KeySchema"] = [{"AttributeName": "orderPk", "KeyType": "HASH"}]


def drop(t):
    del t["Resources"]["OrdersTable"]


def rename(t):
    t["Resources"]["OrderStore"] = t["Resources"].pop("OrdersTable")


def unprotect(t):
    _table(t)["DeletionProtectionEnabled"] = False
    _table(t)["PointInTimeRecoverySpecification"] = {"PointInTimeRecoveryEnabled": False}


def ssh(t):
    t["Resources"]["WebSecurityGroup"]["Properties"]["SecurityGroupIngress"].append(
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"})


def public_queue(t):
    t["Resources"]["OrdersQueuePolicy"]["Properties"]["PolicyDocument"]["Statement"][0]["Principal"] = "*"


def injected_grant(t):
    t["Resources"]["OrdersQueuePolicy"]["Properties"]["PolicyDocument"]["Statement"].append({
        "Sid": "Debug", "Effect": "Allow", "Principal": {"AWS": AAA},
        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
        "Resource": {"Fn::GetAtt": ["OrdersQueue", "Arn"]},
    })


def privesc(t):
    t["Resources"]["OrderWorkerRole"] = {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
        "Policies": [{"PolicyName": "order-worker", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
             "Resource": {"Fn::GetAtt": ["OrdersQueue", "Arn"]}},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}}],
    }}


def leaked_key(t):
    t["Resources"]["IntegrationConfig"] = {"Type": "AWS::SSM::Parameter",
                                           "Properties": {"Type": "String", "Value": "AKIAIOSFODNN7EXAMPLE"}}


def intent_drift(t):
    t["Resources"]["OrdersDLQ"] = {"Type": "AWS::SQS::Queue", "Properties": {"SqsManagedSseEnabled": True}}
    t["Resources"]["OrdersQueue"]["Properties"]["RedrivePolicy"] = {
        "deadLetterTargetArn": {"Fn::GetAtt": ["OrdersDLQ", "Arn"]}, "maxReceiveCount": 5}
    t["Resources"]["WebSecurityGroup"]["Properties"]["SecurityGroupIngress"].append(
        {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "CidrIp": "10.0.0.0/8"})


# (name, mutate, intent, declared scope, expected verdict, axioms that must block)
SCENARIOS = [
    ("Add a lookup index", safe_index, "Add an index so support can look up orders by customer.",
     ["OrdersTable:modify"], "ALLOW", set()),
    ("Rename the partition key", rekey, "Rename the partition key to match our naming convention.",
     ["OrdersTable:modify"], "BLOCK", {"AX-03"}),
    ("Delete the orders table", drop, "Remove resources we no longer use.",
     ["OrdersTable:remove"], "BLOCK", {"AX-01"}),
    ("Refactor: rename a resource", rename, "Refactor: rename OrdersTable to OrderStore.",
     ["OrdersTable:remove", "OrderStore:add"], "BLOCK", {"AX-02"}),
    ("Turn off protections", unprotect, "Cut costs by turning off extras we do not need.",
     ["OrdersTable:modify"], "BLOCK", {"AX-04"}),
    ("Open SSH to the internet", ssh, "Open SSH so I can debug the box quickly.",
     ["WebSecurityGroup:modify"], "BLOCK", {"AX-05"}),
    ("Make the queue public", public_queue, "Let partners send orders directly.",
     ["OrdersQueuePolicy:modify"], "BLOCK", {"AX-11"}),
    ("Prompt-injected access grant", injected_grant, "Fix log retention on the orders queue.",
     ["OrdersQueue:modify"], "BLOCK", {"AX-13", "AX-15"}),
    ("Let a role pass any role", privesc, "Give the order worker the permissions it needs.",
     ["OrderWorkerRole:add"], "BLOCK", {"AX-06", "AX-14"}),
    ("Hardcode an access key", leaked_key, "Store the partner integration config.",
     ["IntegrationConfig:add"], "BLOCK", {"AX-08"}),
    ("Intent drift", intent_drift, "Add a dead-letter queue for failed orders.",
     ["OrdersDLQ:add", "OrdersQueue:modify"], "BLOCK", {"AX-15"}),
]
# Control: the same drift change with every touched resource honestly declared must pass,
# proving AX-15 blocks undeclared changes rather than everything.
CONTROL = ("Control: drift, fully declared", intent_drift, "Add a DLQ and open 8080 to the VPC for the worker.",
           ["OrdersDLQ:add", "OrdersQueue:modify", "WebSecurityGroup:modify"], "ALLOW", set())


def call(base: str, path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method="POST" if data else "GET",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:300]}"}


def run_one(base, baseline, name, mutate, intent, scope, expected, must_block, nonce):
    t = json.loads(json.dumps(baseline))
    mutate(t)
    body = {"template": t, "intent": f"{intent} [{nonce}]" if nonce else intent, "scope": scope}
    res = call(base, "/api/arena/review", body)
    if "error" in res:
        return {"name": name, "ok": False, "verdict": "HTTP-ERROR", "detail": res["error"]}
    r = res["record"]
    blocking = {f["axiom"] for f in r.get("findings", []) if f["severity"] == "BLOCK"}
    checks = ", ".join(f"{c['check'].replace('Check', '')}={c['result']}" for c in r.get("checks", []))
    ok = r["verdict"] == expected and must_block <= blocking
    return {"name": name, "ok": ok, "verdict": r["verdict"], "expected": expected,
            "blocking": ",".join(sorted(blocking)) or "-", "checks": checks or "-",
            "ms": r.get("timing_ms"), "cached": bool(r.get("cached")),
            "report": bool((r.get("assessment") or {}).get("text")), "body": body}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url")
    base = parser.parse_args().base_url.rstrip("/")
    baseline = call(base, "/api/arena/baseline")["template"]
    nonce = f"suite-{int(time.time())}"

    results = []
    for name, mutate, intent, scope, expected, must_block in [*SCENARIOS, CONTROL]:
        results.append(run_one(base, baseline, name, mutate, intent, scope, expected, must_block, nonce))
        time.sleep(1.2)  # the arena route is throttled to 1 request per second

    print(f"{'#':<3}{'SCENARIO':<34}{'EXPECT':<7}{'GOT':<7}{'BLOCKED BY':<20}{'MS':>6}  ACCESS ANALYZER")
    for i, r in enumerate(results, 1):
        mark = "ok " if r["ok"] else "FAIL"
        print(f"{i:<3}{r['name']:<34}{r.get('expected', ''):<7}{r['verdict']:<7}{r.get('blocking', ''):<20}"
              f"{r.get('ms') or '':>6}  {r.get('checks', r.get('detail', ''))}  [{mark}]")

    # Cache check: resubmit the first scenario unchanged.
    repeat = call(base, "/api/arena/review", results[0]["body"])
    cached = bool(repeat.get("record", {}).get("cached"))
    print(f"\ncache: identical resubmission served from cache = {cached}")
    print(f"plain-text report present on all records = {all(r.get('report') for r in results)}")

    failures = [r for r in results if not r["ok"]]
    print(f"\n{len(results) - len(failures)}/{len(results)} scenarios matched expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
