import { Duration, RemovalPolicy } from 'aws-cdk-lib'
import { Match, Template } from 'aws-cdk-lib/assertions'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as kms from 'aws-cdk-lib/aws-kms'
import * as rds from 'aws-cdk-lib/aws-rds'
import * as s3 from 'aws-cdk-lib/aws-s3'

import { collectControlClaims } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { Bucket } from '../src/cmmc2/aws-s3/index.js'
import { DatabaseInstance } from '../src/cmmc2/aws-rds/index.js'
import { EncryptedDatabaseInstance, SecureBucket } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

/**
 * aws-cdk-lib declares Bucket.isWebsite optional but IBucket.isWebsite required,
 * which only conflicts under exactOptionalPropertyTypes. A Bucket is an IBucket.
 */
const asIBucket = (b: s3.Bucket): s3.IBucket => b as s3.IBucket

const POSTGRES = rds.DatabaseInstanceEngine.postgres({
  version: rds.PostgresEngineVersion.VER_16_4,
})
const INSTANCE_TYPE = ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MEDIUM)

function bucketSubject() {
  const { stack } = testStack()
  const encryptionKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })
  const logs = new s3.Bucket(stack, 'Logs', { encryption: s3.BucketEncryption.KMS, encryptionKey })
  const bucket = new Bucket(stack, 'Data', {
    encryptionKey,
    serverAccessLogsBucket: asIBucket(logs),
    serverAccessLogsPrefix: 'data/',
  })
  return { stack, bucket, encryptionKey }
}

function databaseSubject() {
  const { stack, vpc } = testStack()
  const encryptionKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })
  const instance = new DatabaseInstance(stack, 'Db', {
    engine: POSTGRES,
    instanceType: INSTANCE_TYPE,
    vpc,
    vpcSubnets: { subnets: vpc.privateSubnets },
    encryptionKey,
    masterUsername: 'dbadmin',
  })
  return { stack, instance, encryptionKey }
}

describe('Bucket synthesized properties', () => {
  it('encrypts with the supplied customer-managed key', () => {
    const { stack, encryptionKey } = bucketSubject()

    Template.fromStack(stack).hasResourceProperties('AWS::S3::Bucket', {
      BucketEncryption: {
        ServerSideEncryptionConfiguration: [
          Match.objectLike({
            ServerSideEncryptionByDefault: {
              SSEAlgorithm: 'aws:kms',
              KMSMasterKeyID: stack.resolve(encryptionKey.keyArn),
            },
          }),
        ],
      },
    })
  })

  it('blocks all public access, enforces ownership, and versions objects', () => {
    const { stack } = bucketSubject()

    Template.fromStack(stack).hasResourceProperties('AWS::S3::Bucket', {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
      VersioningConfiguration: { Status: 'Enabled' },
      OwnershipControls: { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] },
    })
  })

  it('denies non-TLS requests via bucket policy', () => {
    const { stack } = bucketSubject()

    Template.fromStack(stack).hasResourceProperties('AWS::S3::BucketPolicy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Deny',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          }),
        ]),
      }),
    })
  })

  it('logs object access to the supplied bucket', () => {
    const { stack } = bucketSubject()

    Template.fromStack(stack).hasResourceProperties('AWS::S3::Bucket', {
      LoggingConfiguration: Match.objectLike({ LogFilePrefix: 'data/' }),
    })
  })

  it('defaults to a retaining removal policy', () => {
    const { stack } = bucketSubject()

    Template.fromStack(stack).hasResource('AWS::S3::Bucket', { DeletionPolicy: 'Retain' })
  })

  /**
   * A known constraint, pinned so it stays known.
   *
   * Mandating ObjectOwnership=BucketOwnerEnforced disables ACLs, and CDK's
   * log-delivery wiring sets accessControl=LogDeliveryWrite on the target
   * bucket. The two are mutually exclusive, so a compliant Bucket cannot
   * receive another bucket's access logs. SecureBucket creates a plain bucket
   * for that purpose; disabling ACLs on the data bucket is worth the
   * restriction.
   */
  it('cannot itself serve as another bucket access-log destination', () => {
    const { stack, bucket } = bucketSubject()
    const encryptionKey = new kms.Key(stack, 'Key2', { enableKeyRotation: true })

    expect(
      () =>
        new Bucket(stack, 'Other', {
          encryptionKey,
          serverAccessLogsBucket: bucket as s3.IBucket,
        })
    ).toThrow(/objectOwnership must be set to "ObjectWriter"/)
  })
})

describe('DatabaseInstance synthesized properties', () => {
  it('encrypts storage and Performance Insights with the supplied key', () => {
    const { stack, encryptionKey } = databaseSubject()
    const arn = stack.resolve(encryptionKey.keyArn)

    Template.fromStack(stack).hasResourceProperties('AWS::RDS::DBInstance', {
      StorageEncrypted: true,
      KmsKeyId: arn,
      EnablePerformanceInsights: true,
      PerformanceInsightsKMSKeyId: arn,
    })
  })

  it('is private, protected from deletion, and uses IAM auth', () => {
    const { stack } = databaseSubject()

    Template.fromStack(stack).hasResourceProperties('AWS::RDS::DBInstance', {
      PubliclyAccessible: false,
      DeletionProtection: true,
      EnableIAMDatabaseAuthentication: true,
      AutoMinorVersionUpgrade: true,
      CopyTagsToSnapshot: true,
    })
  })

  it('exports the log set cdk-nag expects for the engine', () => {
    const { stack } = databaseSubject()

    Template.fromStack(stack).hasResourceProperties('AWS::RDS::DBInstance', {
      EnableCloudwatchLogsExports: ['postgresql', 'upgrade'],
    })
  })

  it('generates a CMK-encrypted secret and schedules rotation', () => {
    const { stack, encryptionKey } = databaseSubject()
    const template = Template.fromStack(stack)

    template.hasResourceProperties('AWS::SecretsManager::Secret', {
      KmsKeyId: stack.resolve(encryptionKey.keyArn),
    })
    template.resourceCountIs('AWS::SecretsManager::RotationSchedule', 1)
  })

  it('rejects a backup retention below the minimum', () => {
    const { stack, vpc } = testStack()
    const encryptionKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })

    expect(
      () =>
        new DatabaseInstance(stack, 'Db', {
          engine: POSTGRES,
          instanceType: INSTANCE_TYPE,
          vpc,
          vpcSubnets: { subnets: vpc.privateSubnets },
          encryptionKey,
          masterUsername: 'dbadmin',
          backupRetention: Duration.days(1),
        })
    ).toThrow(/backupRetention must be at least 7 days/)
  })

  it('permits SNAPSHOT, which RDS accepts unlike EFS or S3', () => {
    const { stack, vpc } = testStack()
    const encryptionKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })
    new DatabaseInstance(stack, 'Db', {
      engine: POSTGRES,
      instanceType: INSTANCE_TYPE,
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      encryptionKey,
      masterUsername: 'dbadmin',
      removalPolicy: RemovalPolicy.SNAPSHOT,
    })

    Template.fromStack(stack).hasResource('AWS::RDS::DBInstance', { DeletionPolicy: 'Snapshot' })
  })
})

describe('control claims', () => {
  it('Bucket claims against the practices it configures for', () => {
    const { bucket } = bucketSubject()
    const ids = collectControlClaims(bucket)
      .map(c => c.claim.controlId)
      .sort()

    expect(ids).toEqual([
      'AC.L2-3.1.3',
      'AU.L2-3.3.1',
      'MP.L2-3.8.9',
      'SC.L2-3.13.16',
      'SC.L2-3.13.8',
    ])
  })

  it('DatabaseInstance claims against the practices it configures for', () => {
    const { instance } = databaseSubject()
    const ids = collectControlClaims(instance)
      .map(c => c.claim.controlId)
      .sort()

    expect(ids).toEqual([
      'AC.L2-3.1.3',
      'AU.L2-3.3.1',
      'CM.L2-3.4.1',
      'IA.L2-3.5.3',
      'MP.L2-3.8.9',
      'SC.L2-3.13.16',
    ])
  })

  it('every claim states a caveat and none claims full satisfaction', () => {
    for (const { claim } of [
      ...collectControlClaims(bucketSubject().bucket),
      ...collectControlClaims(databaseSubject().instance),
    ]) {
      expect(claim.satisfaction).not.toBe('full')
      expect(claim.caveat).toBeTruthy()
    }
  })
})

/**
 * Outstanding findings are pinned rather than suppressed, so a future cdk-nag
 * that adds an S3 or RDS rule fails here and someone has to decide about it.
 */
describe('outstanding NIST 800-53 R5 findings', () => {
  it('SecureBucket has only the replication rule, which is a deliberate opt-out', () => {
    const { stack } = testStack()
    new SecureBucket(stack, 'Cui', { bucketName: 'vanguard-cui' })

    expect(
      verifyCompliance(stack)
        .violations.map(v => v.ruleId)
        .sort()
    ).toEqual(['NIST.800.53.R5-S3BucketReplicationEnabled'])
  })

  it('EncryptedDatabaseInstance has only the rotation-Lambda token false positives', () => {
    const { stack, vpc } = testStack()
    new EncryptedDatabaseInstance(stack, 'Cui', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      databaseName: 'vanguardcui',
      engine: POSTGRES,
      instanceType: INSTANCE_TYPE,
    })

    // Both rules flag a security group ingress whose port is an unresolved
    // Fn::GetAtt on the DB endpoint. Neither can be satisfied without turning
    // credential rotation off, which would be a worse outcome than the finding.
    expect(
      verifyCompliance(stack)
        .violations.map(v => v.ruleId)
        .sort()
    ).toEqual(['NIST.800.53.R5-EC2RestrictedCommonPorts', 'NIST.800.53.R5-EC2RestrictedSSH'])
  })
})

describe('pattern composition', () => {
  it('SecureBucket creates a key, a log bucket and the data bucket', () => {
    const { stack } = testStack()
    new SecureBucket(stack, 'Cui', { bucketName: 'vanguard-cui' })
    const template = Template.fromStack(stack)

    template.resourceCountIs('AWS::S3::Bucket', 2)
    template.resourceCountIs('AWS::KMS::Key', 1)
  })

  it('SecureBucket reuses a shared log bucket when given one', () => {
    const { stack } = testStack()
    const shared = new s3.Bucket(stack, 'SharedLogs')
    new SecureBucket(stack, 'Cui', {
      bucketName: 'vanguard-cui',
      serverAccessLogsBucket: asIBucket(shared),
    })

    // The shared bucket plus the data bucket, and no third one created here.
    Template.fromStack(stack).resourceCountIs('AWS::S3::Bucket', 2)
  })

  it('EncryptedDatabaseInstance enrols the instance in a backup plan', () => {
    const { stack, vpc } = testStack()
    new EncryptedDatabaseInstance(stack, 'Cui', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      databaseName: 'vanguardcui',
      engine: POSTGRES,
      instanceType: INSTANCE_TYPE,
    })
    const template = Template.fromStack(stack)

    template.resourceCountIs('AWS::Backup::BackupSelection', 1)
    template.resourceCountIs('AWS::Backup::BackupVault', 1)
    template.resourceCountIs('AWS::RDS::DBInstance', 1)
  })

  it.each([
    ['SecureBucket', () => new SecureBucket(testStack().stack, 'X', { bucketName: 'Not-Lower' })],
  ])('%s rejects a non-lowercase name', (_name, build) => {
    expect(build).toThrow(/must be lowercase/)
  })
})
