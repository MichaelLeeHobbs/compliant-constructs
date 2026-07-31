import type * as sns from 'aws-cdk-lib/aws-sns'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { Trail } from '../aws-cloudtrail/index.js'
import { ConfigurationRecorder, type SnapshotFrequency } from '../aws-config/index.js'
import { Detector } from '../aws-guardduty/index.js'
import { LogGroup } from '../aws-logs/index.js'
import { Hub, type OptionalSecurityStandard } from '../aws-securityhub/index.js'
import { cmmc2Claim } from '../index.js'
import { SecureBucket } from './secure-bucket.js'

export interface AccountBaselineProps {
  /**
   * Name stem for the buckets and log groups created here. Must be lowercase.
   *
   * Typically the account or client name, since this is a per-account posture
   * rather than a per-application one.
   */
  readonly name: string

  /** Standards to enable beyond NIST 800-53 Rev 5, which is always on. */
  readonly additionalStandards?: readonly OptionalSecurityStandard[]

  /** How often AWS Config writes a full snapshot. Defaults to hourly. */
  readonly snapshotFrequency?: SnapshotFrequency

  /** Topic notified of configuration changes. */
  readonly notificationTopic?: sns.ITopic
}

/**
 * The detective half of a CMMC Level 2 posture, for one account and region.
 *
 * Everything else in this library configures individual resources correctly.
 * None of it notices when somebody changes a setting in the console
 * afterwards, or when a credential starts being used from somewhere it should
 * not be. That is what this is for, and it is why the CA and RA domains score
 * nothing without it: those practices are about ongoing monitoring and risk
 * identification, which no amount of resource configuration answers.
 *
 * Composes four things that are each individually easy to forget:
 *
 * - **CloudTrail** - who did what, multi-region, validated, delivered to both
 *   S3 and CloudWatch.
 * - **AWS Config** - what the configuration is and when it changed, across
 *   every supported resource type including global ones.
 * - **Security Hub** - continuous evaluation against NIST 800-53 Rev 5.
 * - **GuardDuty** - active threat detection.
 *
 * Deploy one per account per region. All four services are singletons at that
 * scope, and the constructs throw at synth if you declare a second.
 *
 * This does not enable Amazon Inspector. Vulnerability scanning is a real
 * CMMC requirement (RA.L2-3.11.2) and Inspector is the AWS answer, but it
 * carries per-instance and per-image costs that ought to be a deliberate
 * decision rather than something a baseline construct switches on.
 */
export class AccountBaseline extends Construct {
  readonly trail: Trail
  readonly configRecorder: ConfigurationRecorder
  readonly securityHub: Hub
  readonly guardDuty: Detector
  readonly auditBucket: SecureBucket
  readonly trailLogGroup: LogGroup

  constructor(scope: Construct, id: string, props: AccountBaselineProps) {
    super(scope, id)

    if (props.name !== props.name.toLowerCase()) {
      throw new Error(`name must be lowercase, got "${props.name}"`)
    }

    // One destination for both trail files and configuration snapshots. They
    // have the same audience, the same retention question, and the same
    // "do not let anyone delete this" problem.
    this.auditBucket = new SecureBucket(this, 'AuditBucket', {
      bucketName: `${props.name}-audit`,
    })

    this.trailLogGroup = new LogGroup(this, 'TrailLogGroup')

    this.trail = new Trail(this, 'Trail', {
      bucket: this.auditBucket.bucket,
      cloudWatchLogGroup: this.trailLogGroup,
    })

    this.configRecorder = new ConfigurationRecorder(this, 'ConfigRecorder', {
      deliveryBucket: this.auditBucket.bucket,
      deliveryPrefix: 'config',
      ...(props.snapshotFrequency === undefined
        ? {}
        : { snapshotFrequency: props.snapshotFrequency }),
      ...(props.notificationTopic === undefined
        ? {}
        : { notificationTopic: props.notificationTopic }),
    })

    this.securityHub = new Hub(this, 'SecurityHub', {
      ...(props.additionalStandards === undefined
        ? {}
        : { additionalStandards: props.additionalStandards }),
    })

    this.guardDuty = new Detector(this, 'GuardDuty')

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.5',
        satisfaction: 'partial',
        evidence:
          'CloudTrail, Config and GuardDuty findings all reach Security Hub, giving one place ' +
          'where activity, configuration state and threat detections can be correlated',
        caveat:
          'Puts the records in one place and in a common format. Correlating them for an actual ' +
          'investigation is analysis, and nobody has automated that.',
      }),
      cmmc2Claim({
        practice: 'RA.L2-3.11.1',
        satisfaction: 'supporting',
        evidence:
          'Continuous control evaluation and threat detection produce the findings a risk ' +
          'assessment draws on',
        caveat:
          'Supplies inputs. A risk assessment weighs impact against mission and is a document ' +
          'somebody writes, not an output of any of these services.',
      }),
    ])
  }
}
