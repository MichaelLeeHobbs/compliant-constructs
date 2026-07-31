import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2'
import type * as s3 from 'aws-cdk-lib/aws-s3'
import { type Construct } from 'constructs'

import { addControlClaims, type BucketReference } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'deletionProtection'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof elbv2.ApplicationLoadBalancerProps
  ? true
  : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface ApplicationLoadBalancerProps
  extends Omit<elbv2.ApplicationLoadBalancerProps, MandatedProps> {
  /**
   * Bucket receiving access logs. Required.
   *
   * Must be SSE-S3 encrypted: ELB cannot deliver to a KMS-encrypted bucket, and
   * the CDK rejects the combination outright. Use `ServiceLogBucket` from
   * `cmmc2/patterns`, which exists for exactly this constraint.
   */
  readonly accessLogsBucket: BucketReference

  /** Prefix for delivered log objects. */
  readonly accessLogsPrefix?: string
}

/**
 * An application load balancer configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `elbv2.ApplicationLoadBalancer`. Access logging is
 * required, deletion protection is mandated, and invalid HTTP headers are
 * dropped rather than forwarded.
 *
 * Dropping invalid headers matters more than it sounds: forwarding malformed
 * headers to a backend is the mechanism behind a whole family of request
 * smuggling attacks, and the attribute defaults to off.
 *
 * **`ALBWAFEnabled` is outstanding by design.** Associating a WAF web ACL is a
 * real decision with a real bill, and the right rule set depends entirely on
 * what sits behind the load balancer. Associate one where your risk assessment
 * calls for it; the finding stays visible in the meantime.
 */
export class ApplicationLoadBalancer extends elbv2.ApplicationLoadBalancer {
  constructor(scope: Construct, id: string, props: ApplicationLoadBalancerProps) {
    super(scope, id, {
      ...props,
      deletionProtection: true,
    })

    this.setAttribute('routing.http.drop_invalid_header_fields.enabled', 'true')
    this.logAccessLogs(props.accessLogsBucket as s3.IBucket, props.accessLogsPrefix)

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence: 'Access logs delivered to a dedicated bucket',
        nagRuleIds: ['NIST.800.53.R5-ELBLoggingEnabled'],
        caveat:
          'Records requests reaching the load balancer. Requests handled entirely by a backend, ' +
          'or arriving by another path, are not captured here.',
      }),
      cmmc2Claim({
        practice: 'SI.L2-3.14.1',
        satisfaction: 'supporting',
        evidence:
          'routing.http.drop_invalid_header_fields.enabled=true, so malformed headers are ' +
          'rejected rather than forwarded to a backend',
        nagRuleIds: ['NIST.800.53.R5-ALBHttpDropInvalidHeaderEnabled'],
        caveat:
          'Closes one class of request smuggling. Identifying and correcting flaws generally is ' +
          'a process, not a load balancer attribute.',
      }),
      cmmc2Claim({
        practice: 'CM.L2-3.4.1',
        satisfaction: 'supporting',
        evidence: 'Deletion protection enabled',
        nagRuleIds: ['NIST.800.53.R5-ELBDeletionProtectionEnabled'],
        caveat:
          'Prevents accidental removal of a component in the boundary. Says nothing about the ' +
          'wider configuration baseline.',
      }),
    ])
  }
}
