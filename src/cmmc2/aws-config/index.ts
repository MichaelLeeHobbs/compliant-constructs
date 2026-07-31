import { Stack } from 'aws-cdk-lib'
import * as config from 'aws-cdk-lib/aws-config'
import * as iam from 'aws-cdk-lib/aws-iam'
import type * as sns from 'aws-cdk-lib/aws-sns'
import { Construct } from 'constructs'

import { addControlClaims, type BucketReference } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/** How often AWS Config writes a full configuration snapshot. */
export type SnapshotFrequency = 'One_Hour' | 'Three_Hours' | 'Six_Hours' | 'Twelve_Hours'

export interface ConfigurationRecorderProps {
  /**
   * Bucket receiving configuration snapshots and history. Required.
   *
   * The bucket policy statements AWS Config needs are added for you - without
   * them the delivery channel is created successfully and then silently
   * delivers nothing, which is the worst possible failure mode for an audit
   * record.
   */
  readonly deliveryBucket: BucketReference

  /** Prefix for delivered objects. */
  readonly deliveryPrefix?: string

  /**
   * How often a full snapshot is written. Defaults to hourly.
   *
   * The API also accepts twenty-four hours; it is not offered. Configuration
   * history is continuous regardless, but a daily snapshot makes
   * point-in-time reconstruction coarse enough to be awkward in an incident.
   */
  readonly snapshotFrequency?: SnapshotFrequency

  /** Topic notified of configuration changes and compliance state. */
  readonly notificationTopic?: sns.ITopic
}

/**
 * AWS Config, recording every supported resource type.
 *
 * There is no L2 covering the recorder, so this is a construct rather than a
 * wrapper. It creates the three things AWS Config cannot function without - a
 * service role, the recorder, and a delivery channel - plus the bucket policy
 * that makes delivery actually work.
 *
 * This is the drift backstop the rest of the library relies on. Everything
 * else here evaluates at synth, which says nothing about what happens after
 * somebody changes a setting in the console. Config is what notices.
 *
 * `allSupported` and `includeGlobalResourceTypes` are both mandated. A
 * recorder scoped to a hand-picked list of resource types is a recorder that
 * will miss the thing you did not think of, and IAM - being global - is
 * exactly the thing most often left out by accident.
 *
 * One recorder per account per region; a second in the same stack throws at
 * synth.
 */
export class ConfigurationRecorder extends Construct {
  readonly recorder: config.CfnConfigurationRecorder
  readonly deliveryChannel: config.CfnDeliveryChannel
  readonly role: iam.Role

  constructor(scope: Construct, id: string, props: ConfigurationRecorderProps) {
    super(scope, id)

    assertSingleRecorderPerStack(this)

    const stack = Stack.of(this)
    const bucket = props.deliveryBucket

    this.role = new iam.Role(this, 'Role', {
      assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
      description: 'Allows AWS Config to record resource configuration',
      managedPolicies: [
        // Partition-aware: the ARN differs in GovCloud, and hardcoding
        // `arn:aws:` produces a template that fails at deploy there.
        iam.ManagedPolicy.fromManagedPolicyArn(
          this,
          'ConfigRole',
          stack.formatArn({
            partition: stack.partition,
            service: 'iam',
            region: '',
            account: 'aws',
            resource: 'policy',
            resourceName: 'service-role/AWS_ConfigRole',
          })
        ),
      ],
    })

    grantConfigDelivery(this, this.role, bucket, props.deliveryPrefix)

    this.recorder = new config.CfnConfigurationRecorder(this, 'Recorder', {
      roleArn: this.role.roleArn,
      recordingGroup: {
        allSupported: true,
        includeGlobalResourceTypes: true,
      },
    })

    const frequency = props.snapshotFrequency ?? 'One_Hour'

    this.deliveryChannel = new config.CfnDeliveryChannel(this, 'DeliveryChannel', {
      s3BucketName: bucket.bucketName,
      configSnapshotDeliveryProperties: { deliveryFrequency: frequency },
      ...(props.deliveryPrefix === undefined ? {} : { s3KeyPrefix: props.deliveryPrefix }),
      ...(props.notificationTopic === undefined
        ? {}
        : { snsTopicArn: props.notificationTopic.topicArn }),
    })

    // The recorder is useless without somewhere to deliver to, and
    // CloudFormation will happily create them in the wrong order otherwise.
    this.recorder.addDependency(this.deliveryChannel)

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'CA.L2-3.12.3',
        satisfaction: 'partial',
        evidence:
          `Configuration of every supported resource type, including global resources, recorded ` +
          `continuously with a ${frequency.replace('_', ' ').toLowerCase()} snapshot`,
        caveat:
          'Records what the configuration is and when it changed. Whether a change was authorised ' +
          'is answered by CloudTrail and by change control, not here.',
      }),
      cmmc2Claim({
        practice: 'CM.L2-3.4.1',
        satisfaction: 'partial',
        evidence:
          'Continuous inventory of deployed resources and their configuration, retained in S3',
        caveat:
          'Produces the inventory a baseline is measured against. It does not define the baseline ' +
          'or detect deviation from it unless Config rules are attached.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'supporting',
        evidence: 'Configuration history delivered to S3 and optionally announced on SNS',
        caveat:
          'A record of configuration state over time. It is not an activity log - who made a ' +
          'change is in CloudTrail.',
      }),
    ])
  }
}

/**
 * Add the bucket policy statements AWS Config requires.
 *
 * Config checks it can write before delivering. Without these the channel is
 * created, reports healthy, and never writes anything - so this is not a
 * convenience, it is the difference between having audit records and believing
 * you have them.
 */
function grantConfigDelivery(
  scope: Construct,
  role: iam.Role,
  bucket: BucketReference,
  prefix: string | undefined
): void {
  const objectPath = prefix === undefined ? 'AWSLogs/*' : `${prefix}/AWSLogs/*`

  bucket.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: 'AWSConfigBucketPermissionsCheck',
      principals: [new iam.ServicePrincipal('config.amazonaws.com')],
      actions: ['s3:GetBucketAcl', 's3:ListBucket'],
      resources: [bucket.bucketArn],
    })
  )

  bucket.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: 'AWSConfigBucketDelivery',
      principals: [new iam.ServicePrincipal('config.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [bucket.arnForObjects(objectPath)],
      conditions: { StringEquals: { 's3:x-amz-acl': 'bucket-owner-full-control' } },
    })
  )

  // A managed policy rather than role.addToPolicy, which would create an
  // inline policy and trip IAMNoInlinePolicy. Managed policies are also easier
  // to review and reuse, which is the reason that rule exists.
  role.addManagedPolicy(
    new iam.ManagedPolicy(scope, 'DeliveryPolicy', {
      description: 'Allows AWS Config to write configuration snapshots and history',
      statements: [
        new iam.PolicyStatement({
          actions: ['s3:PutObject', 's3:PutObjectAcl'],
          resources: [bucket.arnForObjects(objectPath)],
        }),
        new iam.PolicyStatement({
          actions: ['s3:GetBucketAcl'],
          resources: [bucket.bucketArn],
        }),
      ],
    })
  )
}

function assertSingleRecorderPerStack(recorder: Construct): void {
  const existing = Stack.of(recorder)
    .node.findAll()
    .filter(c => c !== recorder && c instanceof ConfigurationRecorder)

  if (existing.length > 0) {
    throw new Error(
      `AWS Config allows one configuration recorder per account per region, and ` +
        `${existing[0]?.node.path} already declares one in this stack. Reference that one instead.`
    )
  }
}
