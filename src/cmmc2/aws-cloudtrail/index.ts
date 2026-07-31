import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail'
import type * as s3 from 'aws-cdk-lib/aws-s3'
import type * as kms from 'aws-cdk-lib/aws-kms'
import type * as logs from 'aws-cdk-lib/aws-logs'
import { type Construct } from 'constructs'

import { addControlClaims, type BucketReference } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

/** Props this wrapper takes ownership of. */
type MandatedProps =
  | 'encryptionKey'
  | 'enableFileValidation'
  | 'sendToCloudWatchLogs'
  | 'cloudWatchLogGroup'
  | 'includeGlobalServiceEvents'
  | 'isMultiRegionTrail'
  | 'bucket'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof cloudtrail.TrailProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface TrailProps extends Omit<cloudtrail.TrailProps, MandatedProps> {
  /**
   * Bucket for trail log files. Required.
   *
   * Left to itself CloudTrail creates one, and that bucket is not versioned,
   * not access-logged, and not encrypted with your key. Naming it is how it
   * enters the scope boundary.
   */
  readonly bucket: BucketReference

  /**
   * Log group for the CloudWatch copy of the trail. Required.
   *
   * Delivering to CloudWatch is what makes the trail queryable and alertable
   * rather than an archive nobody reads. Use `LogGroup` from `cmmc2/aws-logs`.
   */
  readonly cloudWatchLogGroup: logs.ILogGroup

  /** Key used to encrypt log files. Defaults to the stack's key. */
  readonly encryptionKey?: kms.IKey
}

/**
 * A CloudTrail trail configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `cloudtrail.Trail`. Log file validation, multi-region
 * coverage, global service events, KMS encryption and CloudWatch delivery are
 * all mandated, and both destinations must be named rather than conjured.
 *
 * This is the construct the AU domain rests on. Without a trail there is no
 * record of who did what to any of the other resources in this library, so the
 * defaults here are deliberately unyielding: a single-region trail with no file
 * validation is close to useless as evidence.
 */
export class Trail extends cloudtrail.Trail {
  constructor(scope: Construct, id: string, props: TrailProps) {
    super(scope, id, {
      ...props,
      bucket: props.bucket as s3.IBucket,
      cloudWatchLogGroup: props.cloudWatchLogGroup,
      encryptionKey: resolveEncryptionKey(scope, props.encryptionKey),
      enableFileValidation: true,
      sendToCloudWatchLogs: true,
      includeGlobalServiceEvents: true,
      isMultiRegionTrail: true,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence:
          'Multi-region trail including global service events, delivered to both S3 and a named ' +
          'CloudWatch log group',
        nagRuleIds: ['NIST.800.53.R5-CloudTrailCloudWatchLogsEnabled'],
        caveat:
          'Records management-plane activity. Data-plane events (S3 object access, Lambda ' +
          'invocations) are only captured if event selectors are configured for them.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.2',
        satisfaction: 'partial',
        evidence: 'Every event records the IAM principal that made the call',
        caveat:
          'Traces actions to an IAM principal. Tracing that principal to an individual person ' +
          'depends on whether roles are assumed with unique identities.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.8',
        satisfaction: 'partial',
        evidence:
          'Log file validation enabled, producing signed digests; log files encrypted with a ' +
          'customer-managed key',
        nagRuleIds: [
          'NIST.800.53.R5-CloudTrailLogFileValidationEnabled',
          'NIST.800.53.R5-CloudTrailEncryptionEnabled',
        ],
        caveat:
          'Digest files make tampering detectable after the fact. They do not make it ' +
          'impossible - that needs S3 Object Lock on the destination bucket.',
      }),
    ])
  }
}
