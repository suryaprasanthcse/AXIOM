# AXIOM: AI coding agents hold proofs, not permissions

**App category:** Workplace Efficiency · **Focus track:** Startup
**Tags:** #workplace-efficiency #startups
**Live app:** https://oocyfygzrk.execute-api.us-west-2.amazonaws.com/
**Built with:** Claude Code (coding agent) on AWS Lambda, Amazon API Gateway, AWS CloudFormation, AWS STS, IAM Access Analyzer and Amazon DynamoDB

> **Try it in 60 seconds:** open the live app, click **"Prompt-injected access grant"**, then **RUN AXIOMS**. A change that claims to "fix log retention" quietly grants another AWS account read access to the orders queue. AXIOM blocks it twice: IAM Access Analyzer proves the new cross-account access, and the agent's own declared scope shows it touched a resource it never mentioned.

---

## The problem: we just gave AI agents the keys

This hackathon asks every builder to connect a coding agent to their AWS account. That's the future of shipping software, and it's also a new attack surface. An agent holding AWS credentials can do anything those credentials allow, whether it's following your instructions, misreading them, or obeying a prompt injection hidden in a GitHub issue it just read.

This isn't hypothetical. In July 2025, an AI coding agent deleted a startup's production database during an explicit code freeze.

Today the usual answer is to have a human read every diff the agent produces. That doesn't scale, and it throws away most of the efficiency the agent was supposed to provide.

## The idea: agents hold proofs, not permissions

With AXIOM, an AI agent's own AWS identity is **view-only**. To change anything, it has to earn a credential:

1. **Declare.** The agent submits a CloudFormation template, a one-line intent, and a **declared scope**: the exact resources it will touch, for example `OrdersDLQ:add, OrdersQueue:modify`.
2. **Compute.** AXIOM's broker asks **AWS CloudFormation** to compute a change set, so AWS itself reports what will be added, modified, replaced or deleted.
3. **Decide.** 15 deterministic axioms and **IAM Access Analyzer's automated-reasoning checks** set the verdict. There is no model anywhere in this path.
4. **Mint.** On ALLOW, **AWS STS** issues a credential that lasts **15 minutes** and can call `cloudformation:ExecuteChangeSet` on **that one change set and nothing else**. The session is tagged with the plan ID and a SHA-256 proof hash, so CloudTrail ties every executed change back to its proof.

Anything outside the plan is denied by IAM itself, not by AXIOM's goodwill. If AXIOM goes down, agents fail closed to read-only.

This is the isolation pattern enterprises use for human admins, zero standing privileges with just-in-time scoped credentials, applied to AI agents and enforced by native AWS primitives.

## What the axioms catch

| Axiom | Blocks |
|---|---|
| AX-01 / AX-02 | Deleting a stateful resource, including the classic CDK refactoring mistake where renaming a construct deletes the old table and creates an empty new one |
| AX-03 | Changes that force a database to be replaced, including CloudFormation's "Conditional" replacements |
| AX-04 | Turning off deletion protection or point-in-time recovery |
| AX-05 | Opening anything except TCP 80/443 to the internet |
| AX-06 / AX-14 | IAM wildcards and privilege escalation (`iam:PassRole` on `*`), proved by Access Analyzer `CheckAccessNotGranted` |
| AX-07 / AX-08 | Removing audit trails; credentials in plaintext |
| AX-11 / AX-13 | Public or cross-account resource policies, proved by Access Analyzer `CheckNoPublicAccess` / `CheckNoNewAccess` |
| **AX-15** | **Any change outside the agent's declared scope.** Deletions must be declared explicitly. |

AX-09, AX-10 and AX-12 warn on always-on cost, removed traffic entry points and disabled encryption.

## Why there's no LLM in the security path (and what replaced it)

Our first design used Claude Haiku on Amazon Bedrock to explain each verdict and to judge whether the agent's stated intent matched what the change actually did. Then Bedrock turned out to be unavailable on our Free-plan account.

Rather than upgrade and take on billing exposure, we asked a better question: **does a model belong in an enforcement path at all?** We decided it doesn't:

- **Prompt injection.** A model that reads agent-controlled templates can be argued with. A rules engine can't: to AXIOM, a template that says "ignore your rules" is just a string.
- **Non-determinism.** The same change must always get the same verdict, or audits mean nothing.
- **Explainability.** Every BLOCK now traces to a named rule or a mathematical proof, never to a model's opinion.

The model had one capability nothing else covered: catching a change whose real effect drifts from its stated intent. We replaced it with **AX-15, declared scope**. Intent becomes a machine-checked contract instead of a sentence. In our "intent drift" scenario, the agent declares a dead-letter queue but also edits the firewall. AX-15 blocks it deterministically. When the same change honestly declares the firewall edit, it's allowed, which shows AX-15 blocks undeclared changes, not everything.

## Live arena: try to break it

The live app is an arena, not a landing page. Every run creates a **real CloudFormation change set** against a live stack (`axiom-arena-baseline`) and runs every check. Arena change sets are evaluated and logged, but never executed and never issued a credential. The 11 one-click scenarios range from a safe index addition (ALLOW) to partition-key rewrites, the construct-rename mistake, SSH open to the world, a public queue, a privilege-escalation role, a hardcoded access key, prompt-injected grants and intent drift. You can also edit the template yourself.

Every verdict lands in a public **ledger** with its proof hash.

## Architecture

```
AI coding agent (view-only IAM role)
   | SigV4-signed: template + intent + declared scope
   v
Amazon API Gateway (HTTP API, IAM authorizer on the agent route, throttled)
   v
Broker Lambda --CreateChangeSet (service role)--> AWS CloudFormation computes the diff
   |--> 15 axioms + IAM Access Analyzer (automated reasoning)  ==> verdict
   |--> Amazon DynamoDB proof ledger (SHA-256 proof hash)
   '--> on ALLOW: AWS STS AssumeRole + session policy (one change set, 900 s, tagged)
                     v
Agent executes ExecuteChangeSet; anything else -> AccessDenied

Arena page: served by its own Lambda with no AWS permissions, same origin as the API (no CORS needed)
```

**Trust boundary, enforced by IAM trust policies:**
- **Agent role:** view-only, with an explicit deny on every CloudFormation write and on assuming other roles.
- **Executor role:** trusts *only* the broker's role.
- **CloudFormation service role:** the only identity that changes demo resources.

**AWS services used:** AWS Lambda (broker and page server), Amazon API Gateway (HTTP API, IAM authorization, per-route throttling), AWS CloudFormation (change sets, service role), AWS CDK, IAM and AWS STS (session policies, session tags), IAM Access Analyzer (custom policy checks), Amazon DynamoDB (ledger with point-in-time recovery), Amazon CloudWatch Logs, plus Amazon SQS, DynamoDB and EC2 security groups as the demo workload.

## Implementation quality: verified in production, not just written

| Test (run against the live deployment) | Result |
|---|---|
| Agent assumes the executor role directly | Denied by IAM |
| Agent creates a change set directly | Denied: explicit deny in an identity-based policy |
| Agent requests a safe stack | ALLOW, 15-minute credential issued |
| That credential lists tables or reads another stack | Denied |
| That credential executes its own change set | `CREATE_COMPLETE` |
| **That same credential deletes the table it just created** | **Denied; the table survives** |
| Destructive key rename | BLOCK (AX-03), no credential |
| Under-declared scope, then honest scope, for an update | BLOCK (AX-15), then ALLOW and `UPDATE_COMPLETE` |
| Arena suite (11 scenarios + 1 control) | **12/12 match** |
| Unit tests (axioms, scope, resolver, report) | **20/20 pass** |

The system's own reports caught one of our bugs. Every change set listed tag changes on resources the agent never touched, because the broker tagged change sets with the plan ID and CloudFormation copies stack-level tags onto every resource. AXIOM's plain-text report surfaced it, and we fixed it before it could pollute anyone's audit trail.

## Zero to Shipped, with $0.00 of fiat exposure

AXIOM runs entirely on an **AWS Free-plan account, by design**. No card is billed, and the architecture had to earn its security within that constraint:

- **No new services to buy.** The guardrail is IAM, STS, CloudFormation change sets and Access Analyzer, which every AWS account already has. No model bill, no per-token cost.
- **Paid checks are budgeted.** Access Analyzer's custom checks cost $0.002 each, drawn from Free-plan credits. Policies a change doesn't touch are never re-checked, so a full 12-scenario arena run costs about **$0.012 in credits**.
- **Denial-of-wallet defense is a security control.** The public arena has a 24-hour result cache, a 250-check daily cap (worst case about $0.50/day in credits), and a 1 request/second limit on its expensive route. Past the cap, fallback checks keep blocking public and privileged grants.
- **Constraints shaped the architecture.** CloudFront wasn't available on a brand-new account, so the page is served by a Lambda function with *zero* AWS permissions, on the same origin as the API.

## How the coding agent was used

**Claude Code (Claude Opus 5.5)** was the engineering team:
- Read the hackathon rules and scored our first idea (a meeting-notes Kanban) against them. It called it too generic and proposed AXIOM instead.
- Designed the trust boundary, then caught its own flaw: minting credentials on the agent's machine would have let the agent bypass the gate, so minting moved server-side.
- Wrote everything: the CDK stack (TypeScript), the broker (Python, standard library plus boto3 only), the arena UI, the agent client, 20 unit tests and the live arena suite.
- Inspected the synthesized IAM trust policies before every deploy, then ran the live end-to-end and arena suites against AWS.
- Diagnosed the Bedrock failure down to the account's Free plan through AWS APIs, and found the tag-propagation bug from AXIOM's own output.
- **Caught our admin access-key file sitting in the project folder before the first commit**, and excluded it from git before anything was staged.

**The human stayed in the loop where it matters.** Claude Code's own safety layer refused to auto-approve deploys that change IAM. Every `cdk deploy` was reviewed and approved by a person, so the agent that built AXIOM was itself working under the principle AXIOM enforces. The human also made the product calls: the category, dropping Bedrock, and staying on the Free plan.

## Proof of coding agent connection

<!-- TODO before publishing: add these screenshots. This section is a pass/fail ship-gate requirement. -->
1. **[Screenshot]** Claude Code session showing the agent running `aws sts get-caller-identity` and the live end-to-end tests against account `<account-id>`.
2. **[Screenshot]** The AWS MCP Server (Agent Toolkit) connected in Claude Code, and CloudTrail events from the agent with `invokedBy: aws-mcp.amazonaws.com`.
3. **[Screenshot]** An AXIOM ledger record whose caller is `arn:aws:sts::<account-id>:assumed-role/axiom-agent-role/ai-coding-agent`: the coding agent's own session, recorded by the system it built.
4. **[Screenshot]** `git log` showing `Co-Authored-By: Claude Opus 5.5`.

## Where it's headed (Startup track)

Every team that hands a coding agent cloud credentials needs an answer to "what stops it?" AXIOM's answer uses only AWS-native enforcement, so it fits inside the account a customer already trusts.

- **Next:** an agent hook so Claude Code and Kiro route `cdk deploy` through AXIOM automatically. CloudFormation Hooks, so the gate holds for every deploy path. Service control policies using `aws:ViaAWSMCPService`, so agent calls through the AWS MCP Server must carry a proof.
- **Product:** a multi-account rollout via StackSets, proof engines running inside the customer's own account, and an AWS Marketplace SaaS listing priced per verified change.
- **Wedge:** every agent-made change produces signed, replayable change-management evidence, the kind of artifact compliance audits ask for.

**Current limits:** JSON templates up to 51,200 bytes, stacks that don't need asset publishing, and a single account. The arena demonstrates the gate but never executes.

---

**Live app:** https://oocyfygzrk.execute-api.us-west-2.amazonaws.com/ · #workplace-efficiency #startups
