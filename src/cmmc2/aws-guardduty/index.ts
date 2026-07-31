import { Stack } from 'aws-cdk-lib'
import * as guardduty from 'aws-cdk-lib/aws-guardduty'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/** How quickly findings reach EventBridge and Security Hub. */
export type FindingPublishingFrequency = 'FIFTEEN_MINUTES' | 'ONE_HOUR'

export interface DetectorProps {
  /**
   * How often findings are published. Defaults to every fifteen minutes.
   *
   * Six hours is the AWS default and is also an option in the API; it is not
   * offered here. A detection capability that reports twice a shift is not
   * meaningfully monitoring anything.
   */
  readonly findingPublishingFrequency?: FindingPublishingFrequency

  /**
   * Optional additional detection features, by name.
   *
   * Left alone, the detector runs the protections GuardDuty enables by
   * default. Feature availability differs by partition - several are absent in
   * GovCloud - so this construct does not force a list that would fail to
   * deploy where you actually operate.
   */
  readonly features?: readonly guardduty.CfnDetector.CFNFeatureConfigurationProperty[]
}

/**
 * Amazon GuardDuty, enabled.
 *
 * There is no L2 for GuardDuty in the CDK, so this is a construct rather than
 * a wrapper. It is deliberately small: GuardDuty's value is that it is on, and
 * the only ways to get it wrong are to leave it off or to publish findings so
 * slowly that nobody sees them.
 *
 * `enable` is mandated, and the publishing frequency is narrowed to fifteen
 * minutes or one hour. The API also accepts six hours, which is the AWS
 * default; it is not representable here, because a detection capability
 * reporting twice a shift does not answer SI.L2-3.14.6 in any useful sense.
 *
 * GuardDuty is one detector per account per region. A second one in the same
 * stack throws at synth rather than failing partway through a deploy.
 */
export class Detector extends Construct {
  readonly detector: guardduty.CfnDetector

  constructor(scope: Construct, id: string, props: DetectorProps = {}) {
    super(scope, id)

    assertSingleDetectorPerStack(this)

    const frequency = props.findingPublishingFrequency ?? 'FIFTEEN_MINUTES'

    this.detector = new guardduty.CfnDetector(this, 'Detector', {
      enable: true,
      findingPublishingFrequency: frequency,
      ...(props.features === undefined ? {} : { features: [...props.features] }),
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SI.L2-3.14.6',
        satisfaction: 'partial',
        evidence:
          `GuardDuty enabled, analysing VPC flow logs, DNS queries and CloudTrail events, ` +
          `publishing findings every ${frequency === 'FIFTEEN_MINUTES' ? '15 minutes' : 'hour'}`,
        caveat:
          'Monitors the traffic and API activity AWS can see. It does not inspect payloads, and ' +
          'nothing here routes a finding to a human - alerting is a separate arrangement.',
      }),
      cmmc2Claim({
        practice: 'SI.L2-3.14.7',
        satisfaction: 'partial',
        evidence:
          'Detects credential misuse, anomalous API calls and communication with known-bad hosts',
        caveat:
          'Identifies use that looks unauthorised to a detector trained on general patterns. ' +
          'Whether a given action was authorised in your organisation is not something it knows.',
      }),
      cmmc2Claim({
        practice: 'RA.L2-3.11.2',
        satisfaction: 'supporting',
        evidence: 'Continuous threat detection across the account',
        caveat:
          'Finds active threats rather than latent vulnerabilities. Vulnerability scanning proper ' +
          'needs Amazon Inspector or an equivalent.',
      }),
    ])
  }
}

function assertSingleDetectorPerStack(detector: Construct): void {
  const existing = Stack.of(detector)
    .node.findAll()
    .filter(c => c !== detector && c instanceof Detector)

  if (existing.length > 0) {
    throw new Error(
      `GuardDuty is one detector per account per region, and ${existing[0]?.node.path} already ` +
        'declares one in this stack. Reference that one instead of creating a second.'
    )
  }
}
