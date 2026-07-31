import { RemovalPolicy } from 'aws-cdk-lib'
import type * as kms from 'aws-cdk-lib/aws-kms'
import * as s3 from 'aws-cdk-lib/aws-s3'
import { type Construct } from 'constructs'

import {
  addControlClaims,
  type BucketReference,
  type NonDestructiveRemovalPolicy,
} from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export { type BucketReference, type NonDestructiveRemovalPolicy } from '../../index.js'

/**
 * Props this wrapper takes ownership of, and therefore removes from the
 * caller's reach entirely.
 */
type MandatedProps =
  | 'encryption'
  | 'encryptionKey'
  | 'blockPublicAccess'
  | 'enforceSSL'
  | 'publicReadAccess'
  | 'versioned'
  | 'objectOwnership'
  | 'removalPolicy'
  | 'serverAccessLogsBucket'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof s3.BucketProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface BucketProps extends Omit<s3.BucketProps, MandatedProps> {
  /**
   * Customer-managed KMS key used for default encryption.
   *
   * Required. SSE-S3 satisfies "encrypted at rest" in the loosest sense, but it
   * leaves key custody entirely with AWS, which is weak evidence for
   * SC.L2-3.13.16 and is what cdk-nag's S3DefaultEncryptionKMS objects to.
   */
  readonly encryptionKey?: kms.IKey

  /**
   * Bucket receiving server access logs. Required.
   *
   * Access logs are the only record of who read an object. Without them
   * AU.L2-3.3.1 has nothing to point at for this bucket.
   */
  readonly serverAccessLogsBucket: BucketReference

  /** Defaults to `RETAIN`. `DESTROY` and `SNAPSHOT` are not representable. */
  readonly removalPolicy?: NonDestructiveRemovalPolicy
}

/**
 * An S3 bucket configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `s3.Bucket`. Encryption with a customer-managed
 * key, full public-access blocking, TLS-only access, versioning, bucket-owner
 * enforced object ownership and server access logging are all mandated.
 *
 * Creates exactly the resources `s3.Bucket` does, so it can replace one in an
 * existing stack without changing construct paths.
 *
 * One cdk-nag finding remains outstanding by design:
 * `S3BucketReplicationEnabled`. Satisfying it means provisioning a second
 * bucket and a replication role, which doubles storage cost and, for CUI in
 * GovCloud, is a data-residency decision this library has no business making
 * silently. Configure replication yourself where your risk assessment calls
 * for it.
 */
export class Bucket extends s3.Bucket {
  constructor(scope: Construct, id: string, props: BucketProps) {
    super(scope, id, {
      ...props,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: resolveEncryptionKey(scope, props.encryptionKey),
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      serverAccessLogsBucket: props.serverAccessLogsBucket as s3.IBucket,
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence:
          'BucketEncryption=KMS with a customer-managed key; default encryption applies to all ' +
          'new objects',
        nagRuleIds: ['NIST.800.53.R5-S3DefaultEncryptionKMS'],
        caveat:
          'Objects written before this setting, or copied in with an explicit override, are not ' +
          'covered. Key custody and rotation are properties of the KMS key.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.8',
        satisfaction: 'partial',
        evidence: 'Bucket policy denies all requests where aws:SecureTransport is false',
        caveat:
          'Enforces TLS at the bucket. Does not evidence protection of CUI in transit elsewhere ' +
          'in the system.',
      }),
      cmmc2Claim({
        practice: 'AC.L2-3.1.3',
        satisfaction: 'partial',
        evidence:
          'BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls and RestrictPublicBuckets all ' +
          'true; ObjectOwnership=BucketOwnerEnforced disables ACLs entirely',
        nagRuleIds: ['NIST.800.53.R5-S3BucketPublicReadProhibited'],
        caveat:
          'Prevents public exposure. Authorised access between principals is governed by IAM ' +
          'and the bucket policy, which the caller supplies.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence: 'Server access logging enabled to a separate bucket',
        nagRuleIds: ['NIST.800.53.R5-S3BucketLoggingEnabled'],
        caveat:
          'Records object-level access to this bucket only. Retention and review of those logs ' +
          'are properties of the destination bucket and of process, not of this resource.',
      }),
      cmmc2Claim({
        practice: 'MP.L2-3.8.9',
        satisfaction: 'supporting',
        evidence: 'Versioning enabled, so overwritten and deleted objects remain recoverable',
        caveat:
          'Versioning is not backup. There is no replication or lifecycle-governed retention ' +
          'here - see SecureBucket, and configure replication if your risk assessment needs it.',
      }),
    ])
  }
}
