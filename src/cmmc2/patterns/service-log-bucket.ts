import { RemovalPolicy } from 'aws-cdk-lib'
import * as s3 from 'aws-cdk-lib/aws-s3'
import { Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { cmmc2Claim } from '../index.js'

export interface ServiceLogBucketProps {
  /** Bucket name. Must be lowercase. */
  readonly bucketName: string

  /** Defaults to `RETAIN`. */
  readonly removalPolicy?: NonDestructiveRemovalPolicy

  /** Lifecycle rules, typically an expiry matching your retention policy. */
  readonly lifecycleRules?: s3.LifecycleRule[]
}

/**
 * A bucket for AWS service log delivery, encrypted with SSE-S3.
 *
 * **This is the one bucket in the library that does not use a customer-managed
 * key, and that is an AWS constraint rather than a choice.** Elastic Load
 * Balancing cannot write access logs to a bucket encrypted with SSE-KMS - the
 * CDK rejects the combination outright, and the delivery would fail regardless.
 * Several other service log destinations have the same limitation.
 *
 * Everything else the compliant `Bucket` mandates still applies: public access
 * fully blocked, TLS-only, versioned, retained.
 *
 * Three cdk-nag findings are outstanding here, all pinned by a test rather
 * than suppressed:
 *
 * - `S3DefaultEncryptionKMS`, for the reason above.
 * - `S3BucketLoggingEnabled`, because a bucket that receives access logs cannot
 *   also deliver its own to itself. Point it at a separate log bucket if your
 *   risk assessment wants logs about the logs.
 * - `S3BucketReplicationEnabled`, the same opt-out the ordinary `Bucket` makes.
 *
 * All three show up in the evidence report - a bucket holding log data under
 * AWS-managed keys, without its own access log, is the truth and something an
 * assessor should see rather than have hidden.
 *
 * Use the ordinary `Bucket` for anything holding CUI. Use this only where an
 * AWS service refuses to deliver to a CMK-encrypted destination.
 */
export class ServiceLogBucket extends Construct {
  readonly bucket: s3.Bucket

  constructor(scope: Construct, id: string, props: ServiceLogBucketProps) {
    super(scope, id)

    if (props.bucketName !== props.bucketName.toLowerCase()) {
      throw new Error(`bucketName must be lowercase, got "${props.bucketName}"`)
    }

    this.bucket = new s3.Bucket(this, 'Bucket', {
      bucketName: props.bucketName,
      // SSE-S3, not KMS. See the class note - this is not an oversight.
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
      ...(props.lifecycleRules === undefined ? {} : { lifecycleRules: props.lifecycleRules }),
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.8',
        satisfaction: 'partial',
        evidence:
          'Log destination is encrypted at rest with SSE-S3, blocks all public access, and ' +
          'requires TLS; versioning is on so a delivered object cannot be silently replaced',
        caveat:
          'Encryption uses AWS-managed keys, not a customer-managed key, because ELB and several ' +
          'other services cannot deliver logs to a KMS-encrypted bucket. Key custody for these ' +
          'records therefore sits with AWS.',
      }),
    ])
  }
}
