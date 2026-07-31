import * as ec2 from 'aws-cdk-lib/aws-ec2'
import type * as logs from 'aws-cdk-lib/aws-logs'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { InterfaceVpcEndpoint, Vpc } from '../aws-ec2/index.js'
import { cmmc2Claim } from '../index.js'

/**
 * AWS services reached privately by default.
 *
 * Chosen because a workload holding CUI will call all of them, and because
 * every one of these calls would otherwise leave the VPC: KMS on every
 * encrypted read, Secrets Manager on every credential fetch, CloudWatch Logs
 * on every log line, and the three Systems Manager endpoints on every
 * administrative session.
 */
const DEFAULT_INTERFACE_SERVICES = [
  'KMS',
  'SECRETS_MANAGER',
  'CLOUDWATCH_LOGS',
  'CLOUDWATCH_MONITORING',
  'SSM',
  'SSM_MESSAGES',
  'EC2_MESSAGES',
  'STS',
  'ECR',
  'ECR_DOCKER',
  'CLOUDTRAIL',
  'CONFIG',
  'ELASTIC_FILESYSTEM',
] as const

export type PrivateService = (typeof DEFAULT_INTERFACE_SERVICES)[number]

/** Services with a FIPS 140-validated endpoint variant in US regions. */
const FIPS_VARIANTS = new Set<PrivateService>([
  'KMS',
  'STS',
  'SSM',
  'ELASTIC_FILESYSTEM',
])

export interface CuiVpcProps {
  /** Number of availability zones. Defaults to two. */
  readonly maxAzs?: number

  /**
   * Address space for the VPC. Defaults to `10.0.0.0/16`.
   *
   * A literal string rather than `IIpAddresses` because the endpoint security
   * groups need the CIDR at synth time, and `vpc.vpcCidrBlock` is a token that
   * cdk-nag reads as possibly-the-internet.
   */
  readonly cidr?: string

  /** Log group for flow logs. Defaults to one created here. */
  readonly flowLogGroup?: logs.ILogGroup

  /**
   * Services reached through an interface endpoint.
   *
   * Defaults to the set a CUI workload cannot avoid calling. Adding to this is
   * cheap; leaving one out means that service is reached over the internet, or
   * not at all.
   */
  readonly privateServices?: readonly PrivateService[]

  /**
   * Prefer FIPS 140-validated endpoints where the service offers one.
   * Defaults to true.
   *
   * SC.L2-3.13.11 requires FIPS-validated cryptography for protecting CUI, and
   * the endpoint you connect to is one of the few parts of that you can
   * actually pin in infrastructure. FIPS endpoints exist only in US regions -
   * which is where CUI has to stay anyway.
   */
  readonly fipsEndpoints?: boolean
}

/**
 * A VPC for CUI workloads with no way out to the internet.
 *
 * Every subnet is isolated. There is no internet gateway, no NAT gateway, and
 * therefore no route by which a compromised workload can reach an arbitrary
 * host - and no route by which CUI can leave except through something you
 * deliberately added.
 *
 * That is only usable because of the endpoints. AWS services are reached
 * through interface and gateway endpoints with private DNS, so KMS, Secrets
 * Manager, CloudWatch and Systems Manager all work normally while none of the
 * traffic crosses the boundary. Administration works through Session Manager,
 * which needs no inbound port at all.
 *
 * Network ACLs allow traffic within the VPC and deny everything else. In a VPC
 * with public subnets, NACLs get complicated enough that people write
 * permissive ones and stop thinking about them; here the rule is simply "the
 * VPC, and nothing else", which is both correct and reviewable.
 *
 * This is the strongest network posture the library offers, and unlike `Vpc`
 * it leaves **no** outstanding cdk-nag findings - `VPCNoUnrestrictedRouteToIGW`
 * cannot fire because there is no internet gateway to route to.
 *
 * If a workload genuinely needs outbound internet access, this is not the
 * construct for it. Use `Vpc`, add egress controls, and be explicit that you
 * have opened the boundary.
 */
export class CuiVpc extends Construct {
  readonly vpc: Vpc
  readonly networkAcl: ec2.NetworkAcl
  readonly interfaceEndpoints: ReadonlyMap<PrivateService, InterfaceVpcEndpoint>
  readonly gatewayEndpoints: readonly ec2.GatewayVpcEndpoint[]
  readonly cidr: string

  constructor(scope: Construct, id: string, props: CuiVpcProps = {}) {
    super(scope, id)

    const cidr = props.cidr ?? '10.0.0.0/16'

    this.vpc = new Vpc(this, 'Vpc', {
      maxAzs: props.maxAzs ?? 2,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'isolated', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
      ],
      ipAddresses: ec2.IpAddresses.cidr(cidr),
      ...(props.flowLogGroup === undefined ? {} : { flowLogGroup: props.flowLogGroup }),
    })

    this.cidr = cidr
    this.networkAcl = this.createNetworkAcl()

    // Gateway endpoints are free and route-table based, so there is no reason
    // for a CUI VPC not to have both.
    this.gatewayEndpoints = [
      this.vpc.addGatewayEndpoint('S3Endpoint', {
        service: ec2.GatewayVpcEndpointAwsService.S3,
      }),
      this.vpc.addGatewayEndpoint('DynamoDbEndpoint', {
        service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
      }),
    ]

    const fips = props.fipsEndpoints ?? true
    const services = props.privateServices ?? DEFAULT_INTERFACE_SERVICES

    const endpoints = new Map<PrivateService, InterfaceVpcEndpoint>()
    for (const service of services) {
      endpoints.set(
        service,
        new InterfaceVpcEndpoint(this, `${service}Endpoint`, {
          // aws-cdk-lib declares members optional on Vpc and required on IVpc,
          // which only conflicts under exactOptionalPropertyTypes. A Vpc is an IVpc.
          vpc: this.vpc as ec2.IVpc,
          allowedCidr: cidr,
          service: resolveService(service, fips),
        })
      )
    }
    this.interfaceEndpoints = endpoints

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.1',
        satisfaction: 'partial',
        evidence:
          'All subnets isolated with no internet or NAT gateway; AWS services reached through ' +
          `${endpoints.size} interface endpoints and 2 gateway endpoints; network ACLs permit ` +
          'traffic within the VPC only',
        caveat:
          'Protects the network boundary. Communications above the network layer, and anything ' +
          'reached through a connection added later, are outside what this establishes.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.7',
        satisfaction: 'partial',
        evidence:
          'No route exists from any subnet to the internet, so a workload cannot hold a session ' +
          'here and an external connection at the same time',
        caveat:
          'Applies to resources inside this VPC. Split tunnelling on an end-user device ' +
          'connecting to it is a client configuration matter.',
      }),
      cmmc2Claim({
        practice: 'AC.L2-3.1.20',
        satisfaction: 'partial',
        evidence: 'The only reachable external systems are the AWS services with an endpoint here',
        caveat:
          'Limits connections to the services you provisioned an endpoint for. It does not ' +
          'verify what those services then do with the data.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.6',
        satisfaction: 'partial',
        evidence:
          'Network ACLs deny by default at the subnet layer, beneath the security groups that ' +
          'deny by default at the instance layer',
        caveat:
          'Two layers of deny-by-default. Rules the caller adds at either layer are their own ' +
          'responsibility.',
      }),
      ...(fips
        ? [
            cmmc2Claim({
              practice: 'SC.L2-3.13.11',
              satisfaction: 'partial',
              evidence:
                'FIPS 140-validated endpoints selected for every service that offers one, so ' +
                'those API calls terminate on validated cryptographic modules',
              caveat:
                'Pins the endpoint, which is the part infrastructure controls. Whether the ' +
                'application itself uses validated cryptography is a property of its code.',
            }),
          ]
        : []),
    ])
  }

  /**
   * Allow the VPC to talk to itself, and nothing else.
   *
   * Network ACLs are stateless, so each direction is stated separately. In a
   * VPC with public subnets this quickly turns into ephemeral port ranges and
   * people give up and allow everything; with no internet in the picture the
   * correct rule is short enough to review.
   */
  private createNetworkAcl(): ec2.NetworkAcl {
    const acl = new ec2.NetworkAcl(this, 'NetworkAcl', {
      vpc: this.vpc as ec2.IVpc,
      subnetSelection: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    })

    const cidr = ec2.AclCidr.ipv4(this.cidr)

    acl.addEntry('AllowInternalIngress', {
      ruleNumber: 100,
      cidr,
      traffic: ec2.AclTraffic.allTraffic(),
      direction: ec2.TrafficDirection.INGRESS,
      ruleAction: ec2.Action.ALLOW,
    })

    acl.addEntry('AllowInternalEgress', {
      ruleNumber: 100,
      cidr,
      traffic: ec2.AclTraffic.allTraffic(),
      direction: ec2.TrafficDirection.EGRESS,
      ruleAction: ec2.Action.ALLOW,
    })

    return acl
  }
}

function resolveService(service: PrivateService, fips: boolean): ec2.InterfaceVpcEndpointAwsService {
  const key = fips && FIPS_VARIANTS.has(service) ? `${service}_FIPS` : service
  const resolved = (ec2.InterfaceVpcEndpointAwsService as unknown as Record<string, unknown>)[key]

  if (resolved === undefined) {
    throw new Error(`aws-cdk-lib has no InterfaceVpcEndpointAwsService.${key}`)
  }

  return resolved as ec2.InterfaceVpcEndpointAwsService
}
