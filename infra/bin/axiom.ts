#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { AxiomStack } from '../lib/axiom-stack';

const app = new App();

const builderPrincipalArn = app.node.tryGetContext('builderPrincipalArn');
if (!builderPrincipalArn) {
  throw new Error('Set the builderPrincipalArn context value (the IAM principal allowed to assume the agent role).');
}

new AxiomStack(app, 'AxiomCore', {
  stackName: 'axiom-core',
  description: 'AXIOM: AI agents hold proofs, not permissions.',
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'us-west-2' },
  builderPrincipalArn,
});
