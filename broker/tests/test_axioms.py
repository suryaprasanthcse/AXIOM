import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import axioms  # noqa: E402
from analyzer import Resolver, _external_accounts  # noqa: E402

BASELINE = json.loads((Path(__file__).resolve().parents[2] / "demo" / "arena-baseline.json").read_text())


def change(action, lid, rtype, replacement=None, details=None, physical="phys-" ):
    c = {"Action": action, "LogicalResourceId": lid, "ResourceType": rtype, "PhysicalResourceId": physical + lid}
    if replacement:
        c["Replacement"] = replacement
    if details:
        c["Details"] = details
    return c


def ids(findings, severity="BLOCK"):
    return sorted(f.axiom for f in findings if f.severity == severity)


class StatefulTests(unittest.TestCase):
    def test_deleting_table_blocks(self):
        after = copy.deepcopy(BASELINE)
        del after["Resources"]["OrdersTable"]
        f = axioms.evaluate([change("Remove", "OrdersTable", "AWS::DynamoDB::Table")], BASELINE, after)
        self.assertEqual(ids(f), ["AX-01"])

    def test_retained_table_is_info_only(self):
        before = copy.deepcopy(BASELINE)
        before["Resources"]["OrdersTable"]["DeletionPolicy"] = "Retain"
        f = axioms.evaluate([change("Remove", "OrdersTable", "AWS::DynamoDB::Table")], before, {"Resources": {}})
        self.assertEqual(ids(f), [])
        self.assertEqual(ids(f, "INFO"), ["AX-01"])

    def test_logical_id_rename_is_flagged_as_rename(self):
        changes = [change("Remove", "OrdersTable", "AWS::DynamoDB::Table"),
                   change("Add", "OrderStore", "AWS::DynamoDB::Table")]
        self.assertEqual(ids(axioms.evaluate(changes, BASELINE, BASELINE)), ["AX-02"])

    def test_key_change_replacement_blocks(self):
        details = [{"Target": {"Attribute": "Properties", "Name": "KeySchema", "RequiresRecreation": "Always"}}]
        f = axioms.evaluate([change("Modify", "OrdersTable", "AWS::DynamoDB::Table", "True", details)],
                            BASELINE, BASELINE)
        self.assertEqual(ids(f), ["AX-03"])
        self.assertIn("KeySchema", f[0].detail)

    def test_protection_removed_blocks(self):
        after = copy.deepcopy(BASELINE)
        after["Resources"]["OrdersTable"]["Properties"]["DeletionProtectionEnabled"] = False
        f = axioms.evaluate([change("Modify", "OrdersTable", "AWS::DynamoDB::Table", "False")], BASELINE, after)
        self.assertEqual(ids(f), ["AX-04"])


class NetworkAndIamTests(unittest.TestCase):
    def test_new_ssh_from_world_blocks_but_https_does_not(self):
        after = copy.deepcopy(BASELINE)
        after["Resources"]["WebSecurityGroup"]["Properties"]["SecurityGroupIngress"].append(
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"})
        f = axioms.evaluate([change("Modify", "WebSecurityGroup", "AWS::EC2::SecurityGroup", "False")], BASELINE, after)
        self.assertEqual(ids(f), ["AX-05"])
        self.assertEqual(ids(axioms.evaluate([], BASELINE, BASELINE)), [])

    def test_admin_wildcard_blocks(self):
        after = copy.deepcopy(BASELINE)
        after["Resources"]["Ops"] = {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": "ops", "PolicyDocument": {
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}}
        self.assertEqual(ids(axioms.evaluate([change("Add", "Ops", "AWS::IAM::Policy")], BASELINE, after)), ["AX-06"])

    def test_plaintext_access_key_blocks(self):
        after = copy.deepcopy(BASELINE)
        after["Resources"]["Cfg"] = {"Type": "AWS::SSM::Parameter",
                                     "Properties": {"Type": "String", "Value": "AKIAIOSFODNN7EXAMPLE"}}
        self.assertEqual(ids(axioms.evaluate([change("Add", "Cfg", "AWS::SSM::Parameter")], BASELINE, after)), ["AX-08"])

    def test_verdict(self):
        self.assertEqual(axioms.verdict([]), "ALLOW")
        self.assertEqual(axioms.verdict([axioms.Finding("AX-09", "WARN", "t", "d")]), "ALLOW")
        self.assertEqual(axioms.verdict([axioms.Finding("AX-01", "BLOCK", "t", "d")]), "BLOCK")


class ScopeTests(unittest.TestCase):
    DRIFT = [change("Add", "OrdersDLQ", "AWS::SQS::Queue"),
             change("Modify", "OrdersQueue", "AWS::SQS::Queue", "False"),
             change("Modify", "WebSecurityGroup", "AWS::EC2::SecurityGroup", "False")]

    def test_undeclared_change_blocks(self):
        f = axioms.scope_findings(self.DRIFT, ["OrdersDLQ:add", "OrdersQueue:modify"])
        self.assertEqual([(x.axiom, x.resource) for x in f if x.severity == "BLOCK"], [("AX-15", "WebSecurityGroup")])

    def test_fully_declared_change_passes(self):
        f = axioms.scope_findings(self.DRIFT, ["OrdersDLQ:add", "OrdersQueue", "WebSecurityGroup:modify"])
        self.assertEqual(ids(f), [])

    def test_removal_must_be_declared_explicitly(self):
        drop = [change("Remove", "OrdersTable", "AWS::DynamoDB::Table")]
        self.assertEqual(ids(axioms.scope_findings(drop, ["OrdersTable"])), ["AX-15"])
        self.assertEqual(ids(axioms.scope_findings(drop, ["OrdersTable:remove"])), [])
        self.assertEqual(ids(axioms.scope_findings(drop, ["OrdersTable:*"])), [])

    def test_knock_on_change_of_declared_resource_is_implied(self):
        knock_on = change("Modify", "OrdersQueuePolicy", "AWS::SQS::QueuePolicy", "False", details=[
            {"ChangeSource": "ResourceReference", "CausingEntity": "OrdersQueue",
             "Target": {"Attribute": "Properties", "Name": "Queues"}}])
        f = axioms.scope_findings([knock_on], ["OrdersQueue:modify"])
        self.assertEqual(ids(f), [])
        self.assertEqual(ids(f, "INFO"), ["AX-15", "AX-15"])  # implied knock-on, declared-but-unchanged
        # The same knock-on caused by an undeclared resource still blocks.
        self.assertEqual(ids(axioms.scope_findings([knock_on], ["OrdersDLQ:add"])), ["AX-15"])

    def test_no_scope_means_rule_not_applied(self):
        self.assertEqual(axioms.scope_findings(self.DRIFT, None), [])

    def test_invalid_scope_rejected(self):
        for bad in ([], ["Orders-Table"], ["OrdersTable:delete"], "OrdersTable", ["x"] * 51):
            with self.assertRaises(ValueError):
                axioms.parse_scope(bad)


class ReportTests(unittest.TestCase):
    def test_report_is_plain_text_and_names_what_decided(self):
        import explain
        findings = [axioms.Finding("AX-03", "BLOCK", "Stateful resource replaced", "KeySchema changed", "OrdersTable").to_dict()]
        checks = [{"check": "CheckNoNewAccess", "resource": "OrdersQueuePolicy", "result": "FAIL", "reasons": ["new principal"]}]
        changes = [{"action": "Modify", "logical_id": "OrdersTable", "type": "AWS::DynamoDB::Table",
                    "replacement": "Conditional", "properties": ["KeySchema"]}]
        out = explain.report("BLOCK", "rename key", ["OrdersTable:modify"], changes, findings, checks, [])
        self.assertTrue(out["headline"].startswith("AX-03"))
        for expected in ("VERDICT  BLOCK", "[AX-03]", "FAIL     CheckNoNewAccess", "replacement=Conditional",
                         "rename key", "OrdersTable:modify"):
            self.assertIn(expected, out["text"])
        self.assertEqual(out["generated_by"], "deterministic report (no model)")


class ResolverTests(unittest.TestCase):
    def test_queue_policy_resolves_to_concrete_arns(self):
        r = Resolver(BASELINE, "841535407298", "us-west-2")
        doc = r.resolve(BASELINE["Resources"]["OrdersQueuePolicy"]["Properties"]["PolicyDocument"])
        st = doc["Statement"][0]
        self.assertEqual(st["Principal"]["AWS"], "arn:aws:iam::841535407298:root")
        self.assertEqual(st["Resource"], "arn:aws:sqs:us-west-2:841535407298:OrdersQueue")

    def test_unchanged_policies_cost_no_paid_checks(self):
        from analyzer import check
        asked = []
        findings, log = check(BASELINE, BASELINE, "841535407298", "us-west-2", lambda n: asked.append(n) or False)
        self.assertEqual((findings, log, asked), ([], [], []))

    def test_privileged_fallback_matches_wildcards(self):
        from analyzer import _privileged_actions_matched
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:Pass*", "Resource": "*"}]}
        self.assertEqual(_privileged_actions_matched(doc), ["iam:PassRole"])
        self.assertEqual(_privileged_actions_matched({"Statement": [{"Effect": "Allow", "Action": "sqs:*"}]}), [])

    def test_external_account_detection(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::444455556666:root",
                                                                      "841535407298"]}, "Action": "sqs:*"}]}
        self.assertEqual(_external_accounts(doc, "841535407298"), {"444455556666"})


if __name__ == "__main__":
    unittest.main()
