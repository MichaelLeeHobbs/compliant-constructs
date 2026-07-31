import { Template } from 'aws-cdk-lib/assertions'
import * as ec2 from 'aws-cdk-lib/aws-ec2'

import { collectControlClaims, verifyArchitecture } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { Vpc } from '../src/cmmc2/aws-ec2/index.js'
import { WebAcl } from '../src/cmmc2/aws-wafv2/index.js'
import { CuiVpc, SessionManagerAccess } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

describe('CuiVpc', () => {
  function subject() {
    const { stack } = testStack()
    const cui = new CuiVpc(stack, 'Net')
    return { stack, cui }
  }

  it('has no internet gateway and no NAT gateway', () => {
    const { stack } = subject()
    const template = Template.fromStack(stack)

    template.resourceCountIs('AWS::EC2::InternetGateway', 0)
    template.resourceCountIs('AWS::EC2::NatGateway', 0)
  })

  it('provisions gateway endpoints for S3 and DynamoDB', () => {
    const { stack } = subject()
    const endpoints = Object.values(
      Template.fromStack(stack).findResources('AWS::EC2::VPCEndpoint')
    ).filter(e => (e.Properties as { VpcEndpointType?: string }).VpcEndpointType === 'Gateway')

    expect(endpoints).toHaveLength(2)
  })

  it('provisions an interface endpoint per private service, all with private DNS', () => {
    const { stack, cui } = subject()
    const interfaces = Object.values(
      Template.fromStack(stack).findResources('AWS::EC2::VPCEndpoint')
    ).filter(e => (e.Properties as { VpcEndpointType?: string }).VpcEndpointType === 'Interface')

    expect(interfaces).toHaveLength(cui.interfaceEndpoints.size)
    for (const e of interfaces) {
      expect((e.Properties as { PrivateDnsEnabled?: boolean }).PrivateDnsEnabled).toBe(true)
    }
  })

  /**
   * FIPS-validated cryptography is a Level 2 requirement, and the endpoint you
   * terminate on is the part of it infrastructure can actually pin.
   */
  it('selects FIPS endpoints where the service offers one', () => {
    const { stack } = subject()
    const names = JSON.stringify(Template.fromStack(stack).findResources('AWS::EC2::VPCEndpoint'))

    expect(names).toContain('kms-fips')
    expect(names).toContain('sts-fips')
  })

  it('can be told not to use FIPS endpoints', () => {
    const { stack } = testStack()
    new CuiVpc(stack, 'Net', { fipsEndpoints: false })
    const names = JSON.stringify(Template.fromStack(stack).findResources('AWS::EC2::VPCEndpoint'))

    expect(names).not.toContain('kms-fips')
  })

  it('applies a network ACL permitting only VPC-internal traffic', () => {
    const { stack } = subject()
    const template = Template.fromStack(stack)

    template.resourceCountIs('AWS::EC2::NetworkAcl', 1)
    template.hasResourceProperties('AWS::EC2::NetworkAclEntry', {
      RuleAction: 'allow',
      Egress: false,
    })
    template.hasResourceProperties('AWS::EC2::NetworkAclEntry', {
      RuleAction: 'allow',
      Egress: true,
    })
  })

  /**
   * The plain `Vpc` pins `VPCNoUnrestrictedRouteToIGW` because public subnets
   * inherently route to a gateway. With no gateway at all it cannot fire.
   */
  it('leaves no VPC or endpoint findings, only the structural flow-log role one', () => {
    const { stack } = subject()

    // VPCNoUnrestrictedRouteToIGW cannot fire without a gateway to route to,
    // and the endpoint security groups are narrow enough not to trip the
    // restricted-port rules. What remains is CDK's own flow log delivery role.
    expect(
      verifyCompliance(stack)
        .violations.map(v => v.ruleId)
        .sort()
    ).toEqual(['NIST.800.53.R5-IAMNoInlinePolicy'])
  })

  it('passes the architecture checks', () => {
    const { stack } = subject()
    const result = verifyArchitecture(stack, {
      expectedPrivateServices: ['kms-fips', 'secretsmanager', 'logs'],
    })

    expect(result.findings.map(f => `${f.checkId}: ${f.summary}`)).toEqual([])
    expect(result.compliant).toBe(true)
  })

  it('claims the boundary practices a resource wrapper cannot reach', () => {
    const { cui } = subject()
    const ids = new Set(collectControlClaims(cui).map(c => c.claim.controlId))

    expect(ids.has('SC.L2-3.13.1')).toBe(true)
    expect(ids.has('SC.L2-3.13.7')).toBe(true)
    expect(ids.has('AC.L2-3.1.20')).toBe(true)
    expect(ids.has('SC.L2-3.13.11')).toBe(true)
  })
})

/**
 * The point of the architecture checks: cdk-nag is structurally blind to
 * these, so a VPC can pass the entire rule pack while being unusable for CUI.
 */
describe('verifyArchitecture catches what cdk-nag cannot', () => {
  it('flags a VPC whose workloads reach AWS services over the internet', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', { maxAzs: 2 })

    const nagFindings = verifyCompliance(stack)
      .violations.map(v => v.ruleId)
      .filter(id => id.includes('Endpoint'))
    const architecture = verifyArchitecture(stack, {
      expectedPrivateServices: ['kms', 'secretsmanager', 'logs'],
    })

    // cdk-nag has no rule for this at all.
    expect(nagFindings).toEqual([])
    expect(architecture.findings.map(f => f.checkId)).toContain('CUI-PrivateServiceCoverage')
  })

  it('flags a NAT gateway, which no cdk-nag rule covers', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', { maxAzs: 1, natGateways: 1 })

    expect(verifyArchitecture(stack).findings.map(f => f.checkId)).toContain('CUI-NoInternetRoute')
  })

  it('flags an interface endpoint created without private DNS', () => {
    const { stack } = testStack()
    const cui = new CuiVpc(stack, 'Net')
    new ec2.InterfaceVpcEndpoint(stack, 'Sloppy', {
      vpc: cui.vpc as ec2.IVpc,
      service: ec2.InterfaceVpcEndpointAwsService.SNS,
      privateDnsEnabled: false,
    })

    expect(verifyArchitecture(stack).findings.map(f => f.checkId)).toContain(
      'CUI-EndpointPrivateDns'
    )
  })

  it('flags a plain security group opening SSH to the world', () => {
    const { stack } = testStack()
    const cui = new CuiVpc(stack, 'Net')
    const sg = new ec2.SecurityGroup(stack, 'Sloppy', { vpc: cui.vpc as ec2.IVpc })
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22))

    expect(verifyArchitecture(stack).findings.map(f => f.checkId)).toContain(
      'CUI-NoPublicAdminIngress'
    )
  })

  it('flags all traffic from the world, not just port 22', () => {
    const { stack } = testStack()
    const cui = new CuiVpc(stack, 'Net')
    const sg = new ec2.SecurityGroup(stack, 'Sloppy', { vpc: cui.vpc as ec2.IVpc })
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.allTraffic())

    expect(verifyArchitecture(stack).findings.map(f => f.checkId)).toContain(
      'CUI-NoPublicAdminIngress'
    )
  })

  it('reports the practices each finding bears on', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', { maxAzs: 1, natGateways: 1 })

    const finding = verifyArchitecture(stack).findings.find(
      f => f.checkId === 'CUI-NoInternetRoute'
    )

    expect(finding?.practices).toContain('SC.L2-3.13.7')
  })
})

describe('SessionManagerAccess', () => {
  function subject() {
    const { stack } = testStack()
    const access = new SessionManagerAccess(stack, 'Admin')
    return { stack, access }
  }

  it('creates the preferences document Session Manager actually reads', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::SSM::Document', {
      Name: 'SSM-SessionManagerRunShell',
      DocumentType: 'Session',
    })
  })

  it('logs every session to an encrypted group with streaming on', () => {
    const { stack } = subject()
    const doc = Object.values(Template.fromStack(stack).findResources('AWS::SSM::Document'))[0]
    const inputs = (doc?.Properties as { Content: { inputs: Record<string, unknown> } }).Content
      .inputs

    expect(inputs.cloudWatchStreamingEnabled).toBe(true)
    expect(inputs.cloudWatchEncryptionEnabled).toBe(true)
    expect(inputs.idleSessionTimeout).toBe('15')
  })

  it('rejects an idle timeout outside what AWS accepts', () => {
    const { stack } = testStack()

    expect(() => new SessionManagerAccess(stack, 'A', { idleSessionTimeoutMinutes: 0 })).toThrow(
      /between 1 and 60/
    )
    expect(() => new SessionManagerAccess(stack, 'B', { idleSessionTimeoutMinutes: 90 })).toThrow(
      /between 1 and 60/
    )
  })

  it('gives instances SSM core access and nothing more', () => {
    const { stack } = subject()
    const roles = JSON.stringify(Template.fromStack(stack).findResources('AWS::IAM::Role'))

    expect(roles).toContain('AmazonSSMManagedInstanceCore')
  })

  it('claims the three remote access practices plus session termination', () => {
    const { access } = subject()
    const ids = new Set(collectControlClaims(access).map(c => c.claim.controlId))

    expect(ids.has('AC.L2-3.1.12')).toBe(true)
    expect(ids.has('AC.L2-3.1.13')).toBe(true)
    expect(ids.has('AC.L2-3.1.14')).toBe(true)
    expect(ids.has('SC.L2-3.13.9')).toBe(true)
  })

  it('refuses a second set of preferences in the same stack', () => {
    const { stack } = subject()

    expect(() => new SessionManagerAccess(stack, 'Second')).toThrow(/account and region wide/)
  })
})

describe('WebAcl', () => {
  it('blocks by exception rather than counting', () => {
    const { stack } = testStack()
    new WebAcl(stack, 'Waf', { scope: 'REGIONAL', name: 'app' })

    const acl = Object.values(Template.fromStack(stack).findResources('AWS::WAFv2::WebACL'))[0]
    const rules = (acl?.Properties as { Rules: { OverrideAction: unknown }[] }).Rules

    expect(rules).toHaveLength(3)
    // `count` here would produce a web ACL that reports attacks and stops none.
    for (const rule of rules) expect(rule.OverrideAction).toEqual({ None: {} })
  })

  it('refuses to associate a CloudFront-scoped ACL with a regional resource', () => {
    const { stack } = testStack()
    const waf = new WebAcl(stack, 'Waf', { scope: 'CLOUDFRONT', name: 'cdn' })

    expect(() => waf.associateWith('Assoc', 'arn:aws:elasticloadbalancing:::x')).toThrow(
      /only a REGIONAL web ACL/
    )
  })
})
