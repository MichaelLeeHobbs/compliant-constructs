import * as ec2 from 'aws-cdk-lib/aws-ec2'
import type * as logs from 'aws-cdk-lib/aws-logs'
import { type Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { LogGroup } from '../aws-logs/index.js'
import { cmmc2Claim } from '../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'restrictDefaultSecurityGroup' | 'flowLogs'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof ec2.VpcProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface VpcProps extends Omit<ec2.VpcProps, MandatedProps> {
  /**
   * Log group for VPC flow logs.
   *
   * Defaults to one created here. Unlike `Function`, which requires the caller
   * to name a log group, this creates one: `ec2.Vpc` already creates a log
   * group of its own when flow logs are configured, so making one here is
   * exactly what the wrapped construct does. The rule the library follows is
   * that a wrapper creates what its construct would have created anyway, and
   * requires a name only for resources that would otherwise never appear in
   * the template at all.
   */
  readonly flowLogGroup?: logs.ILogGroup
}

/**
 * A VPC configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `ec2.Vpc`. Flow logs are always on and go to an
 * encrypted log group, the default security group is stripped of its rules, and
 * public subnets do not auto-assign public IPs.
 *
 * That last one is worth spelling out: `mapPublicIpOnLaunch` defaults to true on
 * public subnets, so anything launched there gets a routable address whether or
 * not anyone intended it. Turning it off means exposure has to be asked for.
 *
 * **`VPCNoUnrestrictedRouteToIGW` is outstanding whenever the VPC has public
 * subnets, and cannot be otherwise.** A public subnet is by definition one with
 * a default route to an internet gateway; the rule is really asking whether you
 * need public subnets at all. Build with `subnetConfiguration` containing only
 * private and isolated tiers and the finding disappears.
 */
export class Vpc extends ec2.Vpc {
  readonly flowLogGroup: logs.ILogGroup

  constructor(scope: Construct, id: string, props: VpcProps = {}) {
    super(scope, id, {
      ...props,
      // Strips the ingress and egress rules AWS puts on the default security
      // group, which otherwise allows unrestricted traffic between anything
      // that lands in it by accident.
      restrictDefaultSecurityGroup: true,
    })

    this.flowLogGroup = props.flowLogGroup ?? new LogGroup(this, 'FlowLogGroup')

    this.addFlowLog('FlowLog', {
      destination: ec2.FlowLogDestination.toCloudWatchLogs(this.flowLogGroup),
      trafficType: ec2.FlowLogTrafficType.ALL,
    })

    for (const subnet of this.publicSubnets) {
      const cfnSubnet = subnet.node.defaultChild as ec2.CfnSubnet
      cfnSubnet.mapPublicIpOnLaunch = false
    }

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence: 'Flow logs for ALL traffic delivered to an encrypted CloudWatch log group',
        nagRuleIds: ['NIST.800.53.R5-VPCFlowLogsEnabled'],
        caveat:
          'Records connection metadata - addresses, ports, bytes, accept or reject. It does not ' +
          'record payloads, so it will not tell you what was transferred.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.6',
        satisfaction: 'partial',
        evidence:
          'Default security group stripped of all rules; public subnets do not auto-assign ' +
          'public IP addresses',
        nagRuleIds: [
          'NIST.800.53.R5-VPCDefaultSecurityGroupClosed',
          'NIST.800.53.R5-VPCSubnetAutoAssignPublicIpDisabled',
        ],
        caveat:
          'Closes the two defaults that grant connectivity nobody asked for. The security groups ' +
          'actually attached to workloads are the caller’s to write.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.5',
        satisfaction: 'partial',
        evidence: 'Subnet tiers separate publicly reachable components from internal ones',
        caveat:
          'Provides the separation only if the caller places workloads in the right tier. This ' +
          'construct builds the boundary; it does not police what crosses it.',
      }),
    ])
  }
}
