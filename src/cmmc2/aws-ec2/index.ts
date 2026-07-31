import * as ec2 from 'aws-cdk-lib/aws-ec2'
import { type Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'allowAllOutbound' | 'allowAllIpv6Outbound'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof ec2.SecurityGroupProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

/** Ports that must never be reachable from the whole internet. */
const NEVER_PUBLIC_PORTS = new Map<number, string>([
  [22, 'SSH'],
  [3389, 'RDP'],
])

export interface SecurityGroupProps extends Omit<ec2.SecurityGroupProps, MandatedProps> {
  /**
   * A description is required, where the CDK generates one.
   *
   * Thirty security groups named "Automatically created Security Group" is a
   * real thing that happens, and it makes a network diagram impossible to
   * review.
   */
  readonly description: string
}

/**
 * A security group configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `ec2.SecurityGroup` that starts closed. The CDK
 * defaults `allowAllOutbound` to true; SC.L2-3.13.6 asks for deny-by-default in
 * both directions, so this mandates false and you open what you need.
 *
 * `addIngressRule` additionally rejects SSH and RDP from `0.0.0.0/0` or `::/0`.
 * That is the runtime half of the design - a peer is a runtime value, so no
 * type can express "not the entire internet", and cdk-nag would only catch it
 * after the fact.
 */
export class SecurityGroup extends ec2.SecurityGroup {
  constructor(scope: Construct, id: string, props: SecurityGroupProps) {
    super(scope, id, {
      ...props,
      allowAllOutbound: false,
      allowAllIpv6Outbound: false,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.6',
        satisfaction: 'partial',
        evidence: 'Created with allowAllOutbound=false and allowAllIpv6Outbound=false',
        caveat:
          'Establishes deny-by-default at this security group. Rules added afterwards, network ' +
          'ACLs, and any other path into the subnet are outside its scope.',
      }),
      cmmc2Claim({
        practice: 'AC.L2-3.1.3',
        satisfaction: 'supporting',
        evidence: 'Remote administration ports cannot be opened to the internet through this construct',
        nagRuleIds: ['NIST.800.53.R5-EC2RestrictedSSH', 'NIST.800.53.R5-EC2RestrictedCommonPorts'],
        caveat:
          'Blocks the specific mistake of exposing SSH or RDP to 0.0.0.0/0. Flow control for CUI ' +
          'depends on the whole rule set, not on one prohibited case.',
      }),
    ])
  }

  /**
   * Add an ingress rule, refusing remote administration from the internet.
   *
   * Throws rather than warning. A security group that quietly accepts a rule
   * exposing SSH to the world has not enforced anything.
   */
  override addIngressRule(
    peer: ec2.IPeer,
    connection: ec2.Port,
    description?: string,
    remoteRule?: boolean
  ): void {
    assertNotPublicAdminAccess(peer, connection)
    super.addIngressRule(peer, connection, description, remoteRule)
  }
}

/** Whether a peer is the entire IPv4 or IPv6 internet. */
function isWholeInternet(peer: ec2.IPeer): boolean {
  return peer.uniqueId === '0.0.0.0/0' || peer.uniqueId === '::/0'
}

function assertNotPublicAdminAccess(peer: ec2.IPeer, connection: ec2.Port): void {
  if (!isWholeInternet(peer)) return

  const rule = connection.toRuleJson() as { fromPort?: number; toPort?: number }
  const from = rule.fromPort
  const to = rule.toPort ?? rule.fromPort

  if (from === undefined || to === undefined) return

  for (const [port, name] of NEVER_PUBLIC_PORTS) {
    if (from <= port && port <= to) {
      throw new Error(
        `refusing to open ${name} (port ${port}) to ${peer.uniqueId}. ` +
          'Restrict the peer to a specific CIDR or security group, or reach the instance through ' +
          'SSM Session Manager instead.'
      )
    }
  }
}

export { Vpc, type VpcProps } from "./vpc.js"
