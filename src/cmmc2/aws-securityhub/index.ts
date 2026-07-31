import { Stack } from 'aws-cdk-lib'
import * as securityhub from 'aws-cdk-lib/aws-securityhub'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/**
 * Security standards this construct can enable.
 *
 * `NIST_800_53_R5` is not in this list because it is not optional - see
 * {@link Hub}.
 */
export type OptionalSecurityStandard =
  /** AWS Foundational Security Best Practices. */
  | 'AWS_FOUNDATIONAL'
  /** CIS AWS Foundations Benchmark v3.0.0. */
  | 'CIS_3'
  /** PCI DSS v3.2.1. Enable only if you actually handle cardholder data. */
  | 'PCI_DSS'

/** Path segment of each standard's ARN, which is partition and region scoped. */
const STANDARD_PATHS: Record<OptionalSecurityStandard | 'NIST_800_53_R5', string> = {
  NIST_800_53_R5: 'standards/nist-800-53/v/5.0.0',
  AWS_FOUNDATIONAL: 'standards/aws-foundational-security-best-practices/v/1.0.0',
  CIS_3: 'standards/cis-aws-foundations-benchmark/v/3.0.0',
  PCI_DSS: 'standards/pci-dss/v/3.2.1',
}

export interface HubProps {
  /**
   * Standards to enable alongside NIST 800-53 Rev 5.
   *
   * Defaults to AWS Foundational Security Best Practices and CIS v3. Pass an
   * empty array to enable only NIST 800-53, which is the minimum this
   * construct will do.
   */
  readonly additionalStandards?: readonly OptionalSecurityStandard[]

  /**
   * Controls to disable, by control ID, with the reason recorded.
   *
   * Disabling a control is an assessment decision, so the reason is required
   * rather than optional - it ends up in the deployed template and is the
   * thing an assessor will ask about.
   */
  readonly disabledControls?: readonly { readonly controlId: string; readonly reason: string }[]
}

/**
 * AWS Security Hub, enabled with the standards CMMC Level 2 assessment rests on.
 *
 * There is no L2 for Security Hub in the CDK, so this is a construct rather
 * than a wrapper. It creates the hub and one `CfnStandard` per enabled
 * standard.
 *
 * **NIST 800-53 Rev 5 is always enabled and cannot be turned off.** CMMC
 * Level 2 practices derive from SP 800-171 Rev 2, which derives from 800-53;
 * that standard is the continuous assessment this library's whole evidence
 * story assumes exists. Enabling Security Hub without it would produce
 * findings about a different framework and evidence for nothing.
 *
 * Standard ARNs are built from the stack's partition and region rather than
 * hardcoded, so this works unchanged in GovCloud - where the ARNs are
 * `arn:aws-us-gov:` and hardcoding `arn:aws:` silently produces a template
 * that fails at deploy.
 *
 * Security Hub is one per account per region. Creating two in the same stack
 * throws rather than failing at deploy time with a less obvious message.
 */
export class Hub extends Construct {
  readonly hub: securityhub.CfnHub
  readonly standards: readonly securityhub.CfnStandard[]

  constructor(scope: Construct, id: string, props: HubProps = {}) {
    super(scope, id)

    assertSingleHubPerStack(this)

    this.hub = new securityhub.CfnHub(this, 'Hub', {
      // We enable standards explicitly below. Letting AWS pick the defaults
      // means the set changes under you when AWS changes its mind.
      enableDefaultStandards: false,
      // Consolidated control findings: one finding per control rather than one
      // per standard per control. Without it a single misconfiguration appears
      // three times and the numbers in a report stop meaning anything.
      controlFindingGenerator: 'SECURITY_CONTROL',
      autoEnableControls: true,
    })

    const enabled = ['NIST_800_53_R5' as const, ...(props.additionalStandards ?? DEFAULT_EXTRA)]
    const disabled = (props.disabledControls ?? []).map(c => ({
      standardsControlArn: c.controlId,
      reason: c.reason,
    }))

    this.standards = enabled.map(standard => {
      const cfn = new securityhub.CfnStandard(this, `Standard${standard}`, {
        standardsArn: Stack.of(this).formatArn({
          service: 'securityhub',
          account: '',
          resource: STANDARD_PATHS[standard],
        }),
        ...(disabled.length === 0 ? {} : { disabledStandardsControls: disabled }),
      })
      cfn.addDependency(this.hub)
      return cfn
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'CA.L2-3.12.3',
        satisfaction: 'partial',
        evidence: `Security Hub enabled with ${enabled.join(', ')}, evaluating controls continuously`,
        caveat:
          'Provides the ongoing evaluation. It does not act on the results - somebody has to ' +
          'triage findings, and that is a process control.',
      }),
      cmmc2Claim({
        practice: 'CA.L2-3.12.1',
        satisfaction: 'supporting',
        evidence: 'Automated control assessment against NIST 800-53 Rev 5, re-evaluated on change',
        caveat:
          'Assesses the technical controls Security Hub knows how to check. A periodic assessment ' +
          'of the whole system, including the organizational practices, is a separate exercise.',
      }),
      cmmc2Claim({
        practice: 'RA.L2-3.11.2',
        satisfaction: 'supporting',
        evidence: 'Security Hub aggregates configuration findings across the account',
        caveat:
          'Covers configuration weaknesses. Software vulnerability scanning needs Amazon Inspector ' +
          'or an equivalent, which this construct does not enable.',
      }),
    ])
  }
}

const DEFAULT_EXTRA: readonly OptionalSecurityStandard[] = ['AWS_FOUNDATIONAL', 'CIS_3']

/**
 * Security Hub is a per-account, per-region singleton.
 *
 * CloudFormation reports this as a fairly opaque failure well into a deploy,
 * so catch it at synth where the message can say what to do about it.
 */
function assertSingleHubPerStack(hub: Construct): void {
  const existing = Stack.of(hub)
    .node.findAll()
    .filter(c => c !== hub && c instanceof Hub)

  if (existing.length > 0) {
    throw new Error(
      `Security Hub is one per account per region, and ${existing[0]?.node.path} already ` +
        'declares it in this stack. Reference that one instead of creating a second.'
    )
  }
}
