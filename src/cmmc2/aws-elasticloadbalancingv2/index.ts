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

/** TLS policies this library will attach to a listener. */
export type ModernSslPolicy =
  | elbv2.SslPolicy.TLS13_RES
  | elbv2.SslPolicy.TLS13_EXT1
  | elbv2.SslPolicy.FORWARD_SECRECY_TLS12_RES_GCM

export interface HttpsListenerOptions
  extends Omit<elbv2.BaseApplicationListenerProps, 'protocol' | 'port' | 'sslPolicy' | 'open'> {
  /**
   * TLS policy. Defaults to `TLS13_RES`, which is TLS 1.3 and 1.2 with
   * forward secrecy and no CBC ciphers.
   *
   * The wider policies AWS offers reach back to TLS 1.0 for compatibility with
   * clients that should not be handling CUI. They are not representable here.
   */
  readonly sslPolicy?: ModernSslPolicy
}

/**
 * Add an HTTPS listener with a modern TLS policy.
 *
 * `addListener` is inherited and can still create a plaintext HTTP listener,
 * which is legitimate for the redirect described below. This is the method to
 * reach for when the listener carries traffic.
 */
export function addHttpsListener(
  loadBalancer: ApplicationLoadBalancer,
  id: string,
  options: HttpsListenerOptions
): elbv2.ApplicationListener {
  const listener = loadBalancer.addListener(id, {
    ...options,
    protocol: elbv2.ApplicationProtocol.HTTPS,
    port: 443,
    sslPolicy: options.sslPolicy ?? elbv2.SslPolicy.TLS13_RES,
  })

  addControlClaims(listener, [
    cmmc2Claim({
      practice: 'SC.L2-3.13.8',
      satisfaction: 'partial',
      evidence: `HTTPS listener on 443 with SSL policy ${options.sslPolicy ?? 'TLS13_RES'}`,
      nagRuleIds: ['NIST.800.53.R5-ALBHttpToHttpsRedirection'],
      caveat:
        'Protects CUI between the client and the load balancer. Traffic from the load balancer ' +
        'to a target uses whatever protocol the target group specifies.',
    }),
    cmmc2Claim({
      practice: 'SC.L2-3.13.15',
      satisfaction: 'partial',
      evidence: 'Server certificate presented on every connection, with TLS 1.2 as the floor',
      caveat:
        'Authenticates the server to the client. Authenticating the client to the server needs ' +
        'mutual TLS or an application-layer mechanism.',
    }),
  ])

  return listener
}

/**
 * Add a plaintext listener that does nothing but redirect to HTTPS.
 *
 * The one legitimate reason to open port 80 on a load balancer carrying CUI:
 * a client that arrives on HTTP gets moved to HTTPS rather than being served.
 */
export function addHttpsRedirect(
  loadBalancer: ApplicationLoadBalancer,
  id = 'HttpRedirect'
): elbv2.ApplicationListener {
  return loadBalancer.addListener(id, {
    protocol: elbv2.ApplicationProtocol.HTTP,
    port: 80,
    defaultAction: elbv2.ListenerAction.redirect({
      protocol: 'HTTPS',
      port: '443',
      permanent: true,
    }),
  })
}
