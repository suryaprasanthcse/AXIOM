# AXIOM: AI agents hold proofs, not permissions

A zero-trust deploy gate for AI coding agents on AWS, built for AWS Builder Center's *Zero to Shipped* hackathon (Workplace Efficiency · Startup).

- **Live app:** https://oocyfygzrk.execute-api.us-west-2.amazonaws.com/
- **Project page:** https://builder.aws.com/project/3K7u8bnc2nRfkWZPa5NlKJkTkOd/axiom-ai-agents-hold-proofs-not-permissions

## The problem

An AI coding agent holding AWS keys can do anything those keys allow, whether it is following your instruction, making a mistake, or obeying a prompt injection hidden in something it read. Reviewing every change by hand doesn't scale, and an LLM reviewer can be wrong or argued with.

## How it works

1. **Declare.** The agent's own IAM role is view-only. It submits a CloudFormation template, an intent, and a declared scope (the exact resources it will touch).
2. **Compute.** AWS CloudFormation computes the change set.
3. **Decide.** Fifteen deterministic rules plus IAM Access Analyzer's automated-reasoning checks set the verdict. There is no LLM in the security path.
4. **Mint.** On ALLOW, AWS STS issues a 15-minute credential that can execute only that change set, tagged with the verdict's proof hash. Everything else is `AccessDenied`, enforced by IAM. If AXIOM is down, agents fail closed.

The public arena runs the same checks against a demo stack but never issues credentials.

## Repository layout

| Path | Contents |
|---|---|
| `infra/` | AWS CDK (TypeScript) stack: roles, Lambda functions, HTTP API, DynamoDB ledger |
| `broker/src/` | The broker Lambda: rules (`axioms.py`), IAM Access Analyzer checks (`analyzer.py`), report, ledger |
| `broker/tests/` | Unit tests (`python -m unittest discover -s broker/tests`) |
| `web/` | Arena page and the permission-less Lambda that serves it |
| `agent/axiom_agent.py` | Client an agent uses instead of `cdk deploy` (`plan`, `execute`, `try`) |
| `scripts/` | Live arena test suite and evidence collection |
| `demo/` | Demo CloudFormation templates |

## Deploy

```bash
cd infra
npm install
npx cdk deploy AxiomCore --profile <profile>
```

## AI Assistance Disclosure

AXIOM was directed and orchestrated by Surya Prasanth R, who set the architecture constraints, made all product and security decisions, and reviewed and approved every production deploy. The code, infrastructure and tests were written by Claude Code (Anthropic) under that direction.

---

Independent project. Not affiliated with or endorsed by AWS.

## License

MIT. See [LICENSE](LICENSE).
