import { RemovalPolicy } from 'aws-cdk-lib'
import * as kms from 'aws-cdk-lib/aws-kms'
import * as s3 from 'aws-cdk-lib/aws-s3'
import { Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { Bucket } from '../aws-s3/index.js'
import { cmmc2Claim } from '../index.js'

export interface SecureBucketProps {
  /** Bucket name. Must be lowercase. */
  readonly bucketName: string

  /** Defaults to `RETAIN`. */
  readonly removalPolicy?: NonDestructiveRemovalPolicy

  /**
   * Existing bucket to receive server access logs.
   *
   * Defaults to one created here. Pointing several buckets at one shared log
   * destination is usually better - access records are easier to protect and
   * review in one place than scattered per-bucket.
   */
  readonly serverAccessLogsBucket?: s3.IBucket

  /** Lifecycle rules for the data bucket. */
  readonly lifecycleRules?: s3.LifecycleRule[]
}

/**
 * An S3 bucket with the key and log destination it needs around it.
 *
 * {@link Bucket} requires a `serverAccessLogsBucket`, and that has to come from
 * somewhere; this creates one when there is no shared log bucket to point at.
 * The log bucket is encrypted with the same customer-managed key, which is what
 * `S3DefaultEncryptionKMS` asks for and what a plain SSE-S3 log bucket fails.
 *
 * Because this creates a subtree, adopting it changes construct paths. It is
 * for new stacks.
 */
export class SecureBucket extends Construct {
  readonly bucket: Bucket
  readonly kmsKey: kms.Key
  readonly serverAccessLogsBucket: s3.IBucket

  constructor(scope: Construct, id: string, props: SecureBucketProps) {
    super(scope, id)

    if (props.bucketName !== props.bucketName.toLowerCase()) {
      throw new Error(`bucketName must be lowercase, got "${props.bucketName}"`)
    }

    const removalPolicy = props.removalPolicy ?? RemovalPolicy.RETAIN

    this.kmsKey = new kms.Key(this, 'Key', {
      description: `CUI encryption key for bucket ${props.bucketName}`,
      enableKeyRotation: true,
      removalPolicy,
    })

    // The cast is aws-cdk-lib's typing, not ours: `Bucket` declares
    // `isWebsite?: boolean` while `IBucket` declares it required, which only
    // conflicts under exactOptionalPropertyTypes. A Bucket is an IBucket.
    this.serverAccessLogsBucket =
      props.serverAccessLogsBucket ??
      (this.createLogBucket(props.bucketName, removalPolicy) as s3.IBucket)

    this.bucket = new Bucket(this, 'Bucket', {
      bucketName: props.bucketName,
      encryptionKey: this.kmsKey,
      serverAccessLogsBucket: this.serverAccessLogsBucket,
      serverAccessLogsPrefix: `${props.bucketName}/`,
      removalPolicy,
      ...(props.lifecycleRules === undefined ? {} : { lifecycleRules: props.lifecycleRules }),
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence:
          'Server access logs delivered to a dedicated bucket that is itself encrypted with a ' +
          'customer-managed key and blocks public access',
        nagRuleIds: ['NIST.800.53.R5-S3DefaultEncryptionKMS'],
        caveat:
          'Evidences that access records exist and are protected. Their retention and review ' +
          'remain process controls.',
      }),
    ])
  }

  private createLogBucket(name: string, removalPolicy: RemovalPolicy): s3.Bucket {
    // Deliberately a plain s3.Bucket rather than our own wrapper: a bucket
    // cannot deliver access logs to itself, and the wrapper requires a
    // destination. Everything else the wrapper mandates is set here by hand.
    return new s3.Bucket(this, 'AccessLogs', {
      bucketName: `${name}-access-logs`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.kmsKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      removalPolicy,
    })
  }
}
