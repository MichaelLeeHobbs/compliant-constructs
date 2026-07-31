import { CfnResource, Stack } from 'aws-cdk-lib'
import { type IConstruct } from 'constructs'

/**
 * A property of the assembled infrastructure that no single construct owns.
 *
 * cdk-nag evaluates one resource at a time, which is the right shape for
 * "is this bucket encrypted" and the wrong shape for "can anything in this
 * subnet reach the internet". The second question is answered by the graph -
 * routes, endpoints, reachability - and a VPC with no endpoints at all,
 * no private administrative path and wide-open egress passes the entire
 * NIST 800-53 R5 pack without a single finding.
 *
 * These checks fill that gap. They are deliberately about architecture rather
 * than configuration.
 */
export interface ArchitectureFinding {
  /** Stable identifier, e.g. `CUI-NoInternetRoute`. */
  readonly checkId: string
  /** What is wrong, in one sentence. */
  readonly summary: string
  /** Construct paths the finding applies to. */
  readonly resources: readonly string[]
  /** CMMC practices this bears on. */
  readonly practices: readonly string[]
}

/** Result of {@link verifyArchitecture}. */
export interface ArchitectureResult {
  readonly compliant: boolean
  readonly findings: readonly ArchitectureFinding[]
}

export interface VerifyArchitectureOptions {
  /**
   * AWS service names the workload calls, lowercase, as they appear in a VPC
   * endpoint service name - `kms`, `secretsmanager`, `logs`.
   *
   * Each one without an endpoint is a connection to an external system that
   * AC.L2-3.1.20 asks you to have limited and verified.
   */
  readonly expectedPrivateServices?: readonly string[]
}

/**
 * Check the architectural properties a per-resource rule engine cannot see.
 *
 * Complements `verifyCompliance` rather than replacing it: that answers
 * "is each resource configured correctly", this answers "does the shape of
 * what you built hold together".
 */
export function verifyArchitecture(
  scope: IConstruct,
  options: VerifyArchitectureOptions = {}
): ArchitectureResult {
  const findings = [
    ...checkNoInternetRoute(scope),
    ...checkPrivateServiceCoverage(scope, options.expectedPrivateServices ?? []),
    ...checkNoPublicIngressToAdminPorts(scope),
    ...checkEndpointsHavePrivateDns(scope),
  ]

  return { compliant: findings.length === 0, findings }
}

/** Every CfnResource of a given type at or below a scope. */
function resourcesOfType(scope: IConstruct, type: string): CfnResource[] {
  return scope.node
    .findAll()
    .filter((c): c is CfnResource => CfnResource.isCfnResource(c) && c.cfnResourceType === type)
}

/**
 * A subnet holding CUI should have no path to an internet gateway.
 *
 * cdk-nag's `VPCNoUnrestrictedRouteToIGW` covers the route table, but only for
 * VPCs it can see the routes of; this states the property directly and reports
 * the NAT gateway case too, which that rule does not.
 */
function checkNoInternetRoute(scope: IConstruct): ArchitectureFinding[] {
  const gateways = [
    ...resourcesOfType(scope, 'AWS::EC2::InternetGateway'),
    ...resourcesOfType(scope, 'AWS::EC2::NatGateway'),
  ]

  if (gateways.length === 0) return []

  return [
    {
      checkId: 'CUI-NoInternetRoute',
      summary:
        'The VPC has an internet or NAT gateway, so a workload here can reach arbitrary external ' +
        'hosts. A VPC holding CUI should reach AWS services through endpoints instead.',
      resources: gateways.map(g => g.node.path),
      practices: ['SC.L2-3.13.1', 'SC.L2-3.13.7', 'AC.L2-3.1.20'],
    },
  ]
}

/**
 * Every AWS service the workload calls should have an endpoint.
 *
 * This is the check that would have caught the gap the whole library had until
 * now: correctly configured resources in a VPC that reached every one of those
 * services over the public internet.
 */
function checkPrivateServiceCoverage(
  scope: IConstruct,
  expected: readonly string[]
): ArchitectureFinding[] {
  if (expected.length === 0) return []

  const present = new Set(
    resourcesOfType(scope, 'AWS::EC2::VPCEndpoint').map(endpointServiceSuffix)
  )

  const missing = expected.filter(service => !present.has(service))
  if (missing.length === 0) return []

  return [
    {
      checkId: 'CUI-PrivateServiceCoverage',
      summary:
        `No VPC endpoint for ${missing.join(', ')}. Calls to those services leave the VPC, so ` +
        'they are connections to external systems rather than private traffic.',
      resources: missing,
      practices: ['AC.L2-3.1.20', 'SC.L2-3.13.1'],
    },
  ]
}

/**
 * `com.amazonaws.us-east-1.kms` -> `kms`.
 *
 * The region in a service name is a token until the stack resolves it, so the
 * rendered value is a Fn::Join rather than a plain string. Resolving first and
 * matching on the trailing segment works for both.
 */
function endpointServiceSuffix(endpoint: CfnResource): string {
  const raw = (endpoint as unknown as { serviceName?: unknown }).serviceName
  const rendered = JSON.stringify(Stack.of(endpoint).resolve(raw) ?? '')
  const match = /.([a-z0-9-]+)"?]?}?"?$/.exec(rendered)
  return match?.[1] ?? ''
}

/**
 * An endpoint without private DNS is an endpoint nothing uses.
 *
 * The wrapper mandates it, but an endpoint created directly from `aws-cdk-lib`
 * elsewhere in the same app would not - and it fails silently, which is the
 * worst way for it to fail.
 */
function checkEndpointsHavePrivateDns(scope: IConstruct): ArchitectureFinding[] {
  const offenders = resourcesOfType(scope, 'AWS::EC2::VPCEndpoint').filter(endpoint => {
    const e = endpoint as unknown as { vpcEndpointType?: string; privateDnsEnabled?: unknown }
    // Gateway endpoints have no private DNS setting; only Interface ones do.
    if (e.vpcEndpointType !== 'Interface') return false
    return e.privateDnsEnabled !== true
  })

  if (offenders.length === 0) return []

  return [
    {
      checkId: 'CUI-EndpointPrivateDns',
      summary:
        'An interface endpoint has private DNS disabled, so the service hostname still resolves ' +
        'to public addresses and traffic continues to leave the VPC.',
      resources: offenders.map(o => o.node.path),
      practices: ['AC.L2-3.1.20', 'SC.L2-3.13.1'],
    },
  ]
}

/**
 * Nothing should accept SSH or RDP from the whole internet.
 *
 * Our `SecurityGroup` refuses to create such a rule, but a plain
 * `ec2.SecurityGroup` anywhere in the app will, and this sees the assembled
 * template rather than the construct that made it.
 */
function checkNoPublicIngressToAdminPorts(scope: IConstruct): ArchitectureFinding[] {
  const offenders: string[] = []

  for (const sg of resourcesOfType(scope, 'AWS::EC2::SecurityGroup')) {
    const rendered = Stack.of(sg).resolve(
      (sg as unknown as { securityGroupIngress?: unknown }).securityGroupIngress
    ) as
      | {
          cidrIp?: string
          cidrIpv6?: string
          fromPort?: number
          toPort?: number
          ipProtocol?: string
        }[]
      | undefined

    if ((rendered ?? []).some(exposesAdminToInternet)) offenders.push(sg.node.path)
  }

  if (offenders.length === 0) return []

  return [
    {
      checkId: 'CUI-NoPublicAdminIngress',
      summary:
        'A security group accepts SSH, RDP or all traffic from the whole internet. Administrative ' +
        'access should be brokered by Session Manager rather than an open port.',
      resources: [...new Set(offenders)],
      practices: ['AC.L2-3.1.12', 'AC.L2-3.1.14', 'SC.L2-3.13.6'],
    },
  ]
}

/** An ingress rule that lets the whole internet reach SSH, RDP, or everything. */
function exposesAdminToInternet(rule: {
  cidrIp?: string
  cidrIpv6?: string
  fromPort?: number
  toPort?: number
  ipProtocol?: string
}): boolean {
  if (rule.cidrIp !== '0.0.0.0/0' && rule.cidrIpv6 !== '::/0') return false
  if (rule.ipProtocol === '-1') return true

  const from = rule.fromPort ?? 0
  const to = rule.toPort ?? 65535
  return [22, 3389].some(port => from <= port && port <= to)
}
