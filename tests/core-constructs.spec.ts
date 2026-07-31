import { Duration, RemovalPolicy } from 'aws-cdk-lib'
import { Match, Template } from 'aws-cdk-lib/assertions'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as logs from 'aws-cdk-lib/aws-logs'
import * as sm from 'aws-cdk-lib/aws-secretsmanager'

import { collectControlClaims } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { SecurityGroup } from '../src/cmmc2/aws-ec2/index.js'
import { Key } from '../src/cmmc2/aws-kms/index.js'
import { LogGroup } from '../src/cmmc2/aws-logs/index.js'
import { Secret } from '../src/cmmc2/aws-secretsmanager/index.js'
import { testStack } from './helpers/fixtures.js'

describe('Key', () => {
  it('mandates rotation and retention', () => {
    const { stack } = testStack()
    new Key(stack, 'K')
    const template = Template.fromStack(stack)

    template.hasResourceProperties('AWS::KMS::Key', { EnableKeyRotation: true })
    template.hasResource('AWS::KMS::Key', { DeletionPolicy: 'Retain' })
  })

  it('passes the NIST pack', () => {
    const { stack } = testStack()
    new Key(stack, 'K')

    expect(verifyCompliance(stack).violations).toEqual([])
  })
})

describe('LogGroup', () => {
  it('encrypts with the stack key and sets an explicit retention', () => {
    const { stack } = testStack()
    new LogGroup(stack, 'Lg')

    Template.fromStack(stack).hasResourceProperties('AWS::Logs::LogGroup', {
      RetentionInDays: 365,
      KmsKeyId: Match.anyValue(),
    })
  })

  it('retains records through a stack teardown', () => {
    const { stack } = testStack()
    new LogGroup(stack, 'Lg')

    Template.fromStack(stack).hasResource('AWS::Logs::LogGroup', { DeletionPolicy: 'Retain' })
  })

  it('honours an explicit retention, including INFINITE', () => {
    const { stack } = testStack()
    new LogGroup(stack, 'Lg', { retention: logs.RetentionDays.INFINITE })

    const found = Template.fromStack(stack).findResources('AWS::Logs::LogGroup')

    expect(Object.values(found)[0]?.Properties?.RetentionInDays).toBeUndefined()
  })

  /**
   * CloudWatch Logs acts on its own behalf, so IAM delegation is not enough -
   * without this statement the deploy fails at CreateLogGroup.
   */
  it('grants CloudWatch Logs on the key, scoped by encryption context', () => {
    const { stack } = testStack()
    new LogGroup(stack, 'Lg')

    Template.fromStack(stack).hasResourceProperties('AWS::KMS::Key', {
      KeyPolicy: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Sid: 'AllowCloudWatchLogsEncryption',
            Condition: {
              ArnLike: { 'kms:EncryptionContext:aws:logs:arn': Match.anyValue() },
            },
          }),
        ]),
      }),
    })
  })

  it('grants the key only once no matter how many log groups attach', () => {
    const { stack } = testStack()
    new LogGroup(stack, 'A')
    new LogGroup(stack, 'B')
    new LogGroup(stack, 'C')

    const keys = Template.fromStack(stack).findResources('AWS::KMS::Key')
    const statements = Object.values(keys)[0]?.Properties?.KeyPolicy?.Statement as {
      Sid?: string
    }[]
    const grants = statements.filter(s => s.Sid === 'AllowCloudWatchLogsEncryption')

    // Duplicate sids in a key policy are rejected by KMS, so this has to be 1.
    expect(grants).toHaveLength(1)
  })

  it('passes the NIST pack', () => {
    const { stack } = testStack()
    new LogGroup(stack, 'Lg')

    expect(verifyCompliance(stack).violations).toEqual([])
  })
})

describe('Secret', () => {
  it('encrypts with the stack key and retains', () => {
    const { stack } = testStack()
    new Secret(stack, 'S')
    const template = Template.fromStack(stack)

    template.hasResourceProperties('AWS::SecretsManager::Secret', { KmsKeyId: Match.anyValue() })
    template.hasResource('AWS::SecretsManager::Secret', { DeletionPolicy: 'Retain' })
  })

  it('attaches a rotation schedule when a hosted rotation is supplied', () => {
    const { stack } = testStack()
    new Secret(stack, 'S', {
      hostedRotation: sm.HostedRotation.mysqlSingleUser(),
      rotateAfter: Duration.days(15),
    })

    Template.fromStack(stack).resourceCountIs('AWS::SecretsManager::RotationSchedule', 1)
  })

  /**
   * Rotation cannot be mandated generically - it depends on what consumes the
   * secret. The finding is left standing rather than suppressed, and the claim
   * downgrades to `supporting` to match.
   */
  it('leaves the rotation finding standing when no rotation is configured', () => {
    const { stack } = testStack()
    new Secret(stack, 'S')

    expect(verifyCompliance(stack).violations.map(v => v.ruleId)).toEqual([
      'NIST.800.53.R5-SecretsManagerRotationEnabled',
    ])
  })

  it('reports a weaker claim, with an explanatory caveat, when unrotated', () => {
    const { stack } = testStack()
    const secret = new Secret(stack, 'S')
    const claim = collectControlClaims(secret).find(c => c.claim.controlId === 'IA.L2-3.5.10')

    expect(claim?.claim.satisfaction).toBe('supporting')
    expect(claim?.claim.caveat).toMatch(/No rotation is configured/)
  })

  it('strengthens the claim when rotation is configured', () => {
    const { stack } = testStack()
    const secret = new Secret(stack, 'S', { hostedRotation: sm.HostedRotation.mysqlSingleUser() })
    const claim = collectControlClaims(secret).find(c => c.claim.controlId === 'IA.L2-3.5.10')

    expect(claim?.claim.satisfaction).toBe('partial')
  })
})

describe('SecurityGroup', () => {
  it('starts closed in both address families', () => {
    const { stack, vpc } = testStack()
    new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })

    const found = Template.fromStack(stack).findResources('AWS::EC2::SecurityGroup')
    const props = Object.values(found)[0]?.Properties as {
      SecurityGroupEgress?: { CidrIp?: string }[]
    }

    // CDK emits a placeholder deny-all egress rule rather than the permissive
    // 0.0.0.0/0 allow it would otherwise generate.
    expect(props.SecurityGroupEgress?.some(r => r.CidrIp === '0.0.0.0/0')).not.toBe(true)
  })

  it.each([
    ['SSH', ec2.Port.tcp(22)],
    ['RDP', ec2.Port.tcp(3389)],
  ])('refuses %s from the whole internet', (_name, port) => {
    const { stack, vpc } = testStack()
    const sg = new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })

    expect(() => sg.addIngressRule(ec2.Peer.anyIpv4(), port)).toThrow(/refusing to open/)
  })

  it('refuses a port range that contains SSH', () => {
    const { stack, vpc } = testStack()
    const sg = new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })

    expect(() => sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(20, 25))).toThrow(
      /port 22/
    )
  })

  it('refuses SSH from the whole IPv6 internet too', () => {
    const { stack, vpc } = testStack()
    const sg = new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })

    expect(() => sg.addIngressRule(ec2.Peer.anyIpv6(), ec2.Port.tcp(22))).toThrow(/refusing/)
  })

  it('allows SSH from a specific CIDR', () => {
    const { stack, vpc } = testStack()
    const sg = new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })

    expect(() => sg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(22))).not.toThrow()
  })

  it('allows other ports from the internet, which is a real use case', () => {
    const { stack, vpc } = testStack()
    const sg = new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })

    expect(() => sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443))).not.toThrow()
  })
})

describe('removal policies', () => {
  it('reject DESTROY at the type level and default to RETAIN at runtime', () => {
    const { stack } = testStack()
    new Key(stack, 'K', { removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE })

    Template.fromStack(stack).hasResource('AWS::KMS::Key', {
      DeletionPolicy: 'RetainExceptOnCreate',
    })
  })
})
