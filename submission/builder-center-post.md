# AXIOM: AI agents hold proofs, not permissions

**Category:** Workplace Efficiency · **Track:** Startup · #workplace-efficiency #startups
**Live:** https://oocyfygzrk.execute-api.us-west-2.amazonaws.com/

An agent with AWS keys can do anything the keys allow. AXIOM makes its role view-only. To change anything, it submits a template and a declared scope (`OrdersDLQ:add, OrdersQueue:modify`). CloudFormation computes the change set. 15 deterministic axioms plus IAM Access Analyzer automated reasoning decide. On ALLOW, STS mints a 15-minute credential for that one change set. Anything else: AccessDenied, by IAM.

**Try it:** click "Prompt-injected access grant", then RUN. Blocked twice: Access Analyzer proves new cross-account access, and the change touches a resource outside the declared scope.

## No LLM in the security path
Bedrock was unavailable on our Free-plan account. We didn't upgrade; we removed the model. Models can be prompt-injected and aren't deterministic. Every BLOCK now traces to a rule or a proof. AX-15 (declared scope) replaced the model's intent check.

## $0.00 fiat exposure
Free plan, no card billed. Access Analyzer checks ($0.002) are cached and capped daily: ~$0.012 in credits per full test run.

## Zero to Shipped
Under 24 hours. CloudFront was blocked on a new account, so a Lambda with no permissions serves the page. Live tests: 12/12 arena checks, 20/20 unit tests, and a minted credential that can't delete the table it created.

## Built by a coding agent
Claude Code wrote the CDK stack, broker, UI and tests, ran every live check, and caught our admin key file before the first commit. A human approved each IAM deploy.
Services: AWS MCP Server (Agent Toolkit), Lambda, API Gateway, CloudFormation, STS, IAM Access Analyzer, DynamoDB.

## Proof of agent connection
<!-- Upload: submission/evidence/1-agent-identity.png -->
Agent: `assumed-role/axiom-agent-role/ai-coding-agent`. Direct writes denied.
<!-- Upload: submission/evidence/2-cloudtrail-proof-chain.png -->
`MATCH ledger proof_hash == CloudTrail tag axiom-proof`
`MATCH ledger key == key that ran ExecuteChangeSet`
Ledger: `/api/arena/plan/1790870119809-1dacf9af`
<!-- Upload: submission/evidence/4-git-coauthor.png -->
<!-- Upload: submission/evidence/5-aws-mcp-server.png -->
CloudTrail: `invokedBy: aws-mcp.amazonaws.com`. Reads allowed, CreateChangeSet denied.

**Next:** CloudFormation Hooks, MCP-aware SCPs, Marketplace.
