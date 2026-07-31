import * as ec2 from 'aws-cdk-lib/aws-ec2'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'privateDnsEnabled' | 'open' | 'securityGroups'

/** Fails to compile if any mandated prop stops existing upstream. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof ec2.InterfaceVpcEndpointProps
  ? true
  : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface InterfaceVpcEndpointProps
  extends Omit<ec2.InterfaceVpcEndpointProps, MandatedProps> {
  /**
   * CIDR permitted to reach the endpoint on 443. Required.
   *
   * A literal rather than `vpc.vpcCidrBlock`, which is a CloudFormation
   * token: cdk-nag cannot prove an unresolved token is not the whole internet,
   * so it flags the rule for SSH and RDP exactly as it does the RDS rotation
   * Lambda. Stating the address space also makes the rule reviewable by a
   * human reading the template.
   */
  readonly allowedCidr: string
}

/**
 * An interface VPC endpoint that traffic will actually use, reachable on 443
 * and nothing else.
 *
 * A drop-in replacement for `ec2.InterfaceVpcEndpoint` with two things
 * mandated.
 *
 * **Private DNS**, because without it the service's public hostname keeps
 * resolving to public addresses: every SDK call continues to leave the VPC
 * while the endpoint sits there costing money and carrying nothing.
 * `AC.L2-3.1.20` asks you to limit connections to external systems, and an
 * endpoint whose DNS was never switched over limits nothing.
 *
 * **Its own security group**, allowing HTTPS from the VPC CIDR only. The CDK
 * default of `open: true` produces a group permitting all traffic from the
 * VPC, which cdk-nag flags for SSH and RDP - correctly, since an endpoint has
 * no business accepting either.
 */
export class InterfaceVpcEndpoint extends ec2.InterfaceVpcEndpoint {
  constructor(scope: Construct, id: string, props: InterfaceVpcEndpointProps) {
    // Built in a child scope so the group belongs to the endpoint that uses it
    // rather than to whatever happened to be constructing it.
    const holder = new Construct(scope, `${id}Sg`)
    const securityGroup = new ec2.SecurityGroup(holder, 'SecurityGroup', {
      vpc: props.vpc,
      description: 'HTTPS from within the VPC to an interface endpoint',
      allowAllOutbound: false,
    })
    securityGroup.addIngressRule(
      ec2.Peer.ipv4(props.allowedCidr),
      ec2.Port.tcp(443),
      'HTTPS from within the VPC'
    )

    const { allowedCidr: _allowedCidr, ...rest } = props

    super(scope, id, {
      ...rest,
      privateDnsEnabled: true,
      open: false,
      securityGroups: [securityGroup],
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AC.L2-3.1.20',
        satisfaction: 'partial',
        evidence:
          'Private DNS enabled, so calls to this service resolve inside the VPC and never reach ' +
          'a public endpoint',
        caveat:
          'Covers this one service. Any AWS service without an endpoint is still reached over ' +
          'the internet, and this construct cannot know which ones your workload calls.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.1',
        satisfaction: 'partial',
        evidence:
          'Service traffic stays on the AWS network, reachable on TCP 443 from the VPC CIDR only',
        caveat:
          'Removes one path across the boundary. Boundary protection as a whole depends on what ' +
          'other routes exist out of the subnet.',
      }),
    ])
  }
}
