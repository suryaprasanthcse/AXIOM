import * as path from 'node:path';
import { Aws, CfnOutput, Duration, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpIamAuthorizer } from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export interface AxiomStackProps extends StackProps {
  /** IAM principal (the human builder) allowed to assume the view-only agent role for demos. */
  readonly builderPrincipalArn: string;
}

const AGENT_ROLE_NAME = 'axiom-agent-role';
const ARENA_STACK = 'axiom-arena-baseline';
/** Paid IAM Access Analyzer checks ($0.002 each) the public arena may spend per UTC day. */
const ARENA_DAILY_CHECKS = 250;
/** Fresh (uncached) arena evaluations per UTC day: bounds Lambda time and ledger writes under abuse. */
const ARENA_DAILY_REVIEWS = 300;

/**
 * AXIOM core: the trust boundary that makes "agents hold proofs, not permissions" true.
 *
 *   agent role (view-only) --signed request--> broker Lambda --AssumeRole + session policy--> executor role
 *                                                   |
 *                                                   +--CreateChangeSet (RoleARN = CFN service role)
 *
 * Only the broker can assume the executor role. Only the CFN service role can change resources.
 * The arena page and its API share one origin (the HTTP API invoke URL), so no CORS is configured.
 */
export class AxiomStack extends Stack {
  constructor(scope: Construct, id: string, props: AxiomStackProps) {
    super(scope, id, props);

    const arn = (service: string, resource: string, region = this.region) =>
      `arn:${Aws.PARTITION}:${service}:${region}:${this.account}:${resource}`;
    const demoStacks = arn('cloudformation', 'stack/axiom-demo-*/*');
    const arenaStacks = arn('cloudformation', 'stack/axiom-arena-*/*');
    const axiomChangeSets = arn('cloudformation', 'changeSet/axiom-*/*');

    // --- Proof ledger ---------------------------------------------------------------
    // Kept on update or delete, cleaned up if the very first create fails (no orphans).
    const ledger = new dynamodb.TableV2(this, 'Ledger', {
      tableName: 'axiom-proof-ledger',
      partitionKey: { name: 'plan_id', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
      globalSecondaryIndexes: [{
        indexName: 'byTime',
        partitionKey: { name: 'feed', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      }],
    });

    // --- CloudFormation service role: the only identity that changes demo resources ---
    const cfnServiceRole = new iam.Role(this, 'CfnServiceRole', {
      roleName: 'axiom-cfn-service-role',
      assumedBy: new iam.ServicePrincipal('cloudformation.amazonaws.com'),
      description: 'CloudFormation applies AXIOM-approved change sets to axiom-demo-* stacks with this role.',
    });
    cfnServiceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ManageDemoTables',
      actions: ['dynamodb:*'],
      resources: [arn('dynamodb', 'table/axiom-demo-*')],
    }));
    cfnServiceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ManageDemoQueues',
      actions: ['sqs:*'],
      resources: [arn('sqs', 'axiom-demo-*')],
    }));
    cfnServiceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ManageDemoSecurityGroups',
      actions: [
        'ec2:CreateSecurityGroup', 'ec2:DeleteSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress',
        'ec2:AuthorizeSecurityGroupEgress', 'ec2:RevokeSecurityGroupIngress', 'ec2:RevokeSecurityGroupEgress',
        'ec2:ModifySecurityGroupRules', 'ec2:CreateTags', 'ec2:DeleteTags', 'ec2:DescribeSecurityGroups',
        'ec2:DescribeSecurityGroupRules', 'ec2:DescribeVpcs',
      ],
      resources: ['*'],
    }));

    // --- Broker role: prepares change sets, runs checks, mints credentials ----------
    const brokerRole = new iam.Role(this, 'BrokerRole', {
      roleName: 'axiom-broker-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
      description: 'AXIOM broker Lambda. The only principal trusted by the executor role.',
    });

    // --- Executor role: trusts only the broker; scoped further per session ---------
    const executorRole = new iam.Role(this, 'ExecutorRole', {
      roleName: 'axiom-executor-role',
      assumedBy: new iam.ArnPrincipal(brokerRole.roleArn).withSessionTags(),
      maxSessionDuration: Duration.hours(1),
      description: 'Minted by the AXIOM broker for 15 minutes, narrowed by a session policy to one change set.',
    });
    executorRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ExecuteApprovedDemoChangeSets',
      actions: [
        'cloudformation:ExecuteChangeSet', 'cloudformation:DescribeChangeSet',
        'cloudformation:DescribeStacks', 'cloudformation:DescribeStackEvents',
      ],
      resources: [demoStacks, axiomChangeSets],
    }));

    brokerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'PrepareChangeSetsWithServiceRoleOnly',
      actions: ['cloudformation:CreateChangeSet'],
      resources: [demoStacks, arenaStacks, axiomChangeSets],
      conditions: { StringEquals: { 'cloudformation:RoleArn': cfnServiceRole.roleArn } },
    }));
    brokerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'InspectAndCleanUpChangeSets',
      actions: [
        'cloudformation:DescribeChangeSet', 'cloudformation:DeleteChangeSet', 'cloudformation:DescribeStacks',
        'cloudformation:GetTemplate', 'cloudformation:DeleteStack',
      ],
      resources: [demoStacks, arenaStacks, axiomChangeSets],
    }));
    brokerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'PassServiceRoleToCloudFormation',
      actions: ['iam:PassRole'],
      resources: [cfnServiceRole.roleArn],
      conditions: { StringEquals: { 'iam:PassedToService': 'cloudformation.amazonaws.com' } },
    }));
    brokerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'MintProofScopedCredentials',
      actions: ['sts:AssumeRole', 'sts:TagSession'],
      resources: [executorRole.roleArn],
    }));
    brokerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AutomatedReasoningPolicyChecks',
      actions: [
        'access-analyzer:CheckNoPublicAccess', 'access-analyzer:CheckNoNewAccess',
        'access-analyzer:CheckAccessNotGranted',
      ],
      resources: ['*'],
    }));
    brokerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'MeasureDataAtRisk',
      actions: ['dynamodb:DescribeTable'],
      resources: [arn('dynamodb', 'table/axiom-*')],
    }));
    ledger.grant(brokerRole, 'dynamodb:PutItem', 'dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:UpdateItem');

    // --- Broker Lambda: standard library + the runtime's boto3 only, no third-party code ---
    const broker = new lambda.Function(this, 'Broker', {
      functionName: 'axiom-broker',
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'broker', 'src'), { exclude: ['__pycache__'] }),
      role: brokerRole,
      memorySize: 512,
      timeout: Duration.seconds(29),
      environment: {
        ACCOUNT_ID: this.account,
        LEDGER_TABLE: ledger.tableName,
        CFN_ROLE_ARN: cfnServiceRole.roleArn,
        EXECUTOR_ROLE_ARN: executorRole.roleArn,
        AGENT_ROLE_NAME,
        ARENA_STACK,
        ARENA_DAILY_CHECKS: String(ARENA_DAILY_CHECKS),
        ARENA_DAILY_REVIEWS: String(ARENA_DAILY_REVIEWS),
      },
      logGroup: new logs.LogGroup(this, 'BrokerLogs', {
        logGroupName: '/aws/lambda/axiom-broker',
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
    });

    // --- Arena UI Lambda: serves the page. No AWS permissions beyond its own logs. ----
    const arenaUi = new lambda.Function(this, 'ArenaUi', {
      functionName: 'axiom-arena-ui',
      runtime: lambda.Runtime.PYTHON_3_13,
      architecture: lambda.Architecture.ARM_64,
      handler: 'server.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'web')),
      memorySize: 256,
      timeout: Duration.seconds(5),
      description: 'Serves the AXIOM arena page (index.html, app.js, style.css).',
      logGroup: new logs.LogGroup(this, 'ArenaUiLogs', {
        logGroupName: '/aws/lambda/axiom-arena-ui',
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
    });

    // --- HTTP API: one origin for the page, the arena API and the IAM-signed agent route ---
    const api = new apigwv2.HttpApi(this, 'Api', { apiName: 'axiom-api', createDefaultStage: false });
    const stage = new apigwv2.HttpStage(this, 'DefaultStage', {
      httpApi: api,
      stageName: '$default',
      autoDeploy: true,
      throttle: { rateLimit: 10, burstLimit: 30 },
    });

    const uiIntegration = new HttpLambdaIntegration('ArenaUiIntegration', arenaUi);
    for (const pagePath of ['/', '/app.js', '/style.css']) {
      api.addRoutes({ path: pagePath, methods: [apigwv2.HttpMethod.GET], integration: uiIntegration });
    }

    const brokerIntegration = new HttpLambdaIntegration('BrokerIntegration', broker);
    const [agentRoute] = api.addRoutes({
      path: '/agent/plan',
      methods: [apigwv2.HttpMethod.POST],
      integration: brokerIntegration,
      authorizer: new HttpIamAuthorizer(),
    });
    const [reviewRoute] = api.addRoutes({
      path: '/api/arena/review',
      methods: [apigwv2.HttpMethod.POST],
      integration: brokerIntegration,
    });
    api.addRoutes({ path: '/api/arena/baseline', methods: [apigwv2.HttpMethod.GET], integration: brokerIntegration });
    api.addRoutes({ path: '/api/arena/ledger', methods: [apigwv2.HttpMethod.GET], integration: brokerIntegration });
    api.addRoutes({
      path: '/api/arena/plan/{plan_id}',
      methods: [apigwv2.HttpMethod.GET],
      integration: brokerIntegration,
    });

    // The two routes that create change sets and run paid checks get tighter limits than page loads.
    const cfnStage = stage.node.defaultChild as apigwv2.CfnStage;
    cfnStage.routeSettings = {
      'POST /api/arena/review': { ThrottlingRateLimit: 1, ThrottlingBurstLimit: 3 },
      'POST /agent/plan': { ThrottlingRateLimit: 2, ThrottlingBurstLimit: 5 },
    };
    cfnStage.node.addDependency(reviewRoute, agentRoute);

    // --- Agent role: what an AI coding agent gets. It can look, and ask for a proof. -----
    const agentRole = new iam.Role(this, 'AgentRole', {
      roleName: AGENT_ROLE_NAME,
      assumedBy: new iam.ArnPrincipal(props.builderPrincipalArn),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('job-function/ViewOnlyAccess')],
      maxSessionDuration: Duration.hours(4),
      description: 'Identity for AI coding agents: view-only. Changes require an AXIOM-minted credential.',
    });
    agentRole.addToPolicy(new iam.PolicyStatement({
      sid: 'RequestProofs',
      actions: ['execute-api:Invoke'],
      resources: [arn('execute-api', `${api.apiId}/*/POST/agent/plan`)],
    }));
    agentRole.addToPolicy(new iam.PolicyStatement({
      sid: 'NoStandingWritePathIntoCloudFormation',
      effect: iam.Effect.DENY,
      actions: [
        'cloudformation:CreateChangeSet', 'cloudformation:ExecuteChangeSet', 'cloudformation:CreateStack',
        'cloudformation:UpdateStack', 'cloudformation:DeleteStack', 'cloudformation:DeleteChangeSet',
      ],
      resources: ['*'],
    }));
    agentRole.addToPolicy(new iam.PolicyStatement({
      sid: 'NoRoleHopping',
      effect: iam.Effect.DENY,
      actions: ['sts:AssumeRole', 'sts:TagSession', 'iam:PassRole'],
      resources: ['*'],
    }));

    new CfnOutput(this, 'ArenaUrl', { value: `${api.apiEndpoint}/` });
    new CfnOutput(this, 'AgentPlanEndpoint', { value: `${api.apiEndpoint}/agent/plan` });
    new CfnOutput(this, 'AgentRoleArn', { value: agentRole.roleArn });
    new CfnOutput(this, 'ExecutorRoleArn', { value: executorRole.roleArn });
    new CfnOutput(this, 'CfnServiceRoleArn', { value: cfnServiceRole.roleArn });
    new CfnOutput(this, 'ArenaStackName', { value: ARENA_STACK });
  }
}
