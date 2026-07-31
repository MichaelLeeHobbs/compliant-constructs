/**
 * Generate this library's own coverage documentation.
 *
 * Builds a reference app containing every construct the library ships, collects
 * the control claims from the resulting construct tree, and renders the report
 * set through the `attest` CLI - so the CLI is exercised on every docs build
 * rather than only in tests.
 *
 * Runs against `dist/`, not `src/`, so what gets documented is what gets
 * published. Requires `pnpm run build` first.
 *
 * Pass `--check` to fail instead of writing, for CI.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const docsDir = join(root, 'docs')
const attestationPath = join(docsDir, 'attestation.json')

const { App } = await import('aws-cdk-lib')
const ec2 = await import('aws-cdk-lib/aws-ec2')
const kms = await import('aws-cdk-lib/aws-kms')

const rds = await import('aws-cdk-lib/aws-rds')
const sm = await import('aws-cdk-lib/aws-secretsmanager')
const dynamodb = await import('aws-cdk-lib/aws-dynamodb')
const lambda = await import('aws-cdk-lib/aws-lambda')

const { CompliantStack } = await import('../dist/cmmc2/index.mjs')
const { SecurityGroup, Vpc } = await import('../dist/cmmc2/aws-ec2/index.mjs')
const { Cluster, FargateService, FargateTaskDefinition } =
  await import('../dist/cmmc2/aws-ecs/index.mjs')
const ecs = await import('aws-cdk-lib/aws-ecs')
const { Key } = await import('../dist/cmmc2/aws-kms/index.mjs')
const { LogGroup } = await import('../dist/cmmc2/aws-logs/index.mjs')
const { Secret } = await import('../dist/cmmc2/aws-secretsmanager/index.mjs')
const { Queue } = await import('../dist/cmmc2/aws-sqs/index.mjs')
const { Topic } = await import('../dist/cmmc2/aws-sns/index.mjs')
const { Table } = await import('../dist/cmmc2/aws-dynamodb/index.mjs')
const { Trail } = await import('../dist/cmmc2/aws-cloudtrail/index.mjs')
const { ApplicationLoadBalancer } =
  await import('../dist/cmmc2/aws-elasticloadbalancingv2/index.mjs')
const { FileSystem } = await import('../dist/cmmc2/aws-efs/index.mjs')
const { Bucket } = await import('../dist/cmmc2/aws-s3/index.mjs')
const { DatabaseInstance } = await import('../dist/cmmc2/aws-rds/index.mjs')
const {
  EncryptedDatabaseInstance,
  EncryptedFileSystem,
  SecureBucket,
  SecureFunction,
  ServiceLogBucket,
} = await import('../dist/cmmc2/patterns/index.mjs')
const { buildAttestation } = await import('../dist/report/index.mjs')
const { verifyCompliance } = await import('../dist/verify.mjs')
const { main } = await import('../dist/cli/attest.mjs')

/**
 * A reference deployment exercising every construct the library ships.
 *
 * The VPC is imported rather than created: a real `ec2.Vpc` would add subnets,
 * route tables and a gateway whose claims are not this library's to make.
 */
function referenceApp() {
  const app = new App()
  const stack = new CompliantStack(app, 'ReferenceStack', {
    env: { account: '111111111111', region: 'us-east-1' },
    requiredTags: {
      project: 'reference',
      owner: 'platform',
      environment: 'prod',
      containsCui: true,
    },
  })

  const vpc = ec2.Vpc.fromVpcAttributes(stack, 'Vpc', {
    vpcId: 'vpc-0aa11bb22cc33dd44',
    availabilityZones: ['us-east-1a', 'us-east-1b'],
    privateSubnetIds: ['subnet-0aa11bb22cc33dd01', 'subnet-0aa11bb22cc33dd02'],
    privateSubnetRouteTableIds: ['rtb-0aa11bb22cc33dd01', 'rtb-0aa11bb22cc33dd02'],
  })
  const vpcSubnets = { subnets: vpc.privateSubnets }

  new EncryptedFileSystem(stack, 'CuiStorage', {
    vpc,
    vpcSubnets,
    fileSystemName: 'reference-cui',
  })

  const key = new kms.Key(stack, 'StandaloneKey', { enableKeyRotation: true })
  new FileSystem(stack, 'StandaloneFileSystem', { vpc, vpcSubnets, kmsKey: key })

  const cuiBucket = new SecureBucket(stack, 'CuiBucket', { bucketName: 'reference-cui' })
  // Reuses the log bucket SecureBucket created. A compliant Bucket cannot itself
  // be a log destination: ObjectOwnership=BucketOwnerEnforced disables the ACL
  // that CDK's log-delivery wiring sets on the target.
  new Bucket(stack, 'StandaloneBucket', {
    encryptionKey: key,
    serverAccessLogsBucket: cuiBucket.serverAccessLogsBucket,
    serverAccessLogsPrefix: 'standalone/',
  })

  const engine = rds.DatabaseInstanceEngine.postgres({
    version: rds.PostgresEngineVersion.VER_16_4,
  })
  const instanceType = ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MEDIUM)

  new EncryptedDatabaseInstance(stack, 'CuiDatabase', {
    vpc,
    vpcSubnets,
    databaseName: 'referencecui',
    engine,
    instanceType,
  })
  new DatabaseInstance(stack, 'StandaloneDatabase', {
    vpc,
    vpcSubnets,
    engine,
    instanceType,
    encryptionKey: key,
    masterUsername: 'dbadmin',
  })

  new Key(stack, 'DedicatedKey')
  new LogGroup(stack, 'ApplicationLogs')
  new Secret(stack, 'ApiCredential')
  new Secret(stack, 'RotatedCredential', {
    hostedRotation: sm.HostedRotation.mysqlSingleUser(),
  })
  new SecurityGroup(stack, 'ServiceSecurityGroup', {
    vpc,
    description: 'Reference service security group',
  })

  new Queue(stack, 'WorkQueue')
  new Topic(stack, 'Notifications')
  new Table(stack, 'Records', {
    partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
  })
  const realVpc = new Vpc(stack, 'Network', { maxAzs: 2 })
  const cluster = new Cluster(stack, 'Cluster', { vpc: realVpc })
  const taskLogs = new LogGroup(stack, 'TaskLogs')
  const taskDefinition = new FargateTaskDefinition(stack, 'TaskDefinition', {
    cpu: 256,
    memoryLimitMiB: 512,
  })
  taskDefinition.addComplianceContainer('app', {
    image: ecs.ContainerImage.fromRegistry('public.ecr.aws/nginx/nginx:latest'),
    logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'app', logGroup: taskLogs }),
  })
  new FargateService(stack, 'Service', { cluster, taskDefinition })

  const serviceLogs = new ServiceLogBucket(stack, 'ServiceLogs', {
    bucketName: 'reference-service-logs',
  })
  new ApplicationLoadBalancer(stack, 'Alb', {
    vpc,
    internetFacing: false,
    accessLogsBucket: serviceLogs.bucket,
  })
  new Trail(stack, 'Trail', {
    bucket: cuiBucket.bucket,
    cloudWatchLogGroup: new LogGroup(stack, 'TrailLogs'),
  })

  new SecureFunction(stack, 'Processor', {
    runtime: lambda.Runtime.NODEJS_22_X,
    handler: 'index.handler',
    code: lambda.Code.fromInline('exports.handler = async () => {}'),
  })

  return stack
}

const stack = referenceApp()
const { violations } = verifyCompliance(stack)
const attestation = buildAttestation(stack, { violations })

const check = process.argv.includes('--check')
const serialized = `${JSON.stringify(attestation, null, 2)}\n`

if (!check) {
  mkdirSync(docsDir, { recursive: true })
  writeFileSync(attestationPath, serialized, 'utf8')
}

const argv = [
  '--input',
  attestationPath,
  '--out',
  docsDir,
  '--update',
  join(root, 'README.md'),
  ...(check ? ['--check'] : []),
]

const code = main(argv)

if (check && code === 0) {
  // The CLI checked the rendered reports; the attestation itself still has to
  // match, or a claim could change without any rendered output moving.
  const { readFileSync } = await import('node:fs')
  const onDisk = readFileSync(attestationPath, 'utf8')
  if (onDisk !== serialized) {
    console.error(`attest: ${attestationPath} is stale. Run \`pnpm run coverage:build\`.`)
    process.exit(1)
  }
}

process.exit(code)
