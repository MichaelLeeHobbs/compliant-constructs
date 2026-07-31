import { Template } from 'aws-cdk-lib/assertions'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as ecs from 'aws-cdk-lib/aws-ecs'
import * as s3 from 'aws-cdk-lib/aws-s3'

import { verifyCompliance } from '../src/verify.js'
import { buildAttestation, renderEvidenceCsv } from '../src/report/index.js'
import { SecurityGroup } from '../src/cmmc2/aws-ec2/index.js'
import { FargateTaskDefinition } from '../src/cmmc2/aws-ecs/index.js'
import { LogGroup } from '../src/cmmc2/aws-logs/index.js'
import { Bucket } from '../src/cmmc2/aws-s3/index.js'
import { ServiceLogBucket } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

/**
 * Attempts to defeat the guarantees this library advertises.
 *
 * Every case here found a real hole at least once. They stay as tests because
 * a guarantee nobody attacks is a guarantee nobody has checked.
 */

describe('SecurityGroup ingress guard cannot be sidestepped by port shape', () => {
  function attempt(port: ec2.Port): { blocked: boolean } {
    const { stack, vpc } = testStack()
    const sg = new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })
    try {
      sg.addIngressRule(ec2.Peer.anyIpv4(), port)
      return { blocked: false }
    } catch {
      return { blocked: true }
    }
  }

  // Port.allTraffic() emits ipProtocol '-1' with no port range. An earlier
  // version read fromPort first and returned early, so the broadest and most
  // dangerous rule of all was the one that got through.
  it.each([
    ['allTraffic', ec2.Port.allTraffic()],
    ['allTcp', ec2.Port.allTcp()],
    ['tcp(22)', ec2.Port.tcp(22)],
    ['tcp(3389)', ec2.Port.tcp(3389)],
    ['tcpRange spanning 22', ec2.Port.tcpRange(1, 65535)],
  ])('blocks %s from the whole internet', (_name, port) => {
    expect(attempt(port).blocked).toBe(true)
  })

  // Over-blocking is its own failure: a guard that fires on things it should
  // not is a guard people route around. SSH and RDP are TCP.
  it.each([
    ['udp(22)', ec2.Port.udp(22)],
    ['tcp(443)', ec2.Port.tcp(443)],
    ['tcp(80)', ec2.Port.tcp(80)],
  ])('allows %s from the whole internet', (_name, port) => {
    expect(attempt(port).blocked).toBe(false)
  })

  it('cannot be bypassed through the connections helper', () => {
    const { stack, vpc } = testStack()
    const sg = new SecurityGroup(stack, 'Sg', { vpc, description: 'test' })

    expect(() => sg.connections.allowFrom(ec2.Peer.anyIpv4(), ec2.Port.tcp(22))).toThrow(
      /refusing to open/
    )
  })
})

describe('ECS container hardening cannot be sidestepped', () => {
  /**
   * The hardening used to live on a separate `addComplianceContainer`, leaving
   * the inherited `addContainer` wide open - so the more obvious method name
   * was the insecure one.
   */
  it('applies to addContainer, the method people will actually call', () => {
    const { stack } = testStack()
    const logGroup = new LogGroup(stack, 'Lg')
    const td = new FargateTaskDefinition(stack, 'Td', { cpu: 256, memoryLimitMiB: 512 })

    td.addContainer('app', {
      image: ecs.ContainerImage.fromRegistry('nginx'),
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'a', logGroup }),
      // Cast away the Omit and try to set what the class owns.
      ...({ privileged: true, readonlyRootFilesystem: false } as object),
    })

    const defs = Object.values(
      Template.fromStack(stack).findResources('AWS::ECS::TaskDefinition')
    )[0]?.Properties?.ContainerDefinitions as {
      Privileged: boolean
      ReadonlyRootFilesystem: boolean
    }[]

    expect(defs[0]?.Privileged).toBe(false)
    expect(defs[0]?.ReadonlyRootFilesystem).toBe(true)
  })

  it('refuses a container with no log driver, at runtime as well as in the types', () => {
    const { stack } = testStack()
    const td = new FargateTaskDefinition(stack, 'Td', { cpu: 256, memoryLimitMiB: 512 })

    expect(() =>
      td.addContainer('app', {
        image: ecs.ContainerImage.fromRegistry('nginx'),
      } as unknown as Parameters<typeof td.addContainer>[1])
    ).toThrow(/needs a log driver/)
  })
})

describe('mandated props cannot be smuggled through the spread', () => {
  it('ignores a cast-away override of every property the wrapper owns', () => {
    const { stack } = testStack()
    const logs = new ServiceLogBucket(stack, 'L', { bucketName: 'smuggle-logs' })

    new Bucket(stack, 'B', {
      serverAccessLogsBucket: logs.bucket,
      ...({
        encryption: s3.BucketEncryption.S3_MANAGED,
        versioned: false,
        enforceSSL: false,
        blockPublicAccess: undefined,
      } as object),
    })

    const buckets = Object.values(Template.fromStack(stack).findResources('AWS::S3::Bucket'))
    const data = buckets.find(b => JSON.stringify(b).includes('aws:kms'))

    expect(data).toBeDefined()
    expect(
      (data?.Properties as { VersioningConfiguration?: { Status: string } }).VersioningConfiguration
        ?.Status
    ).toBe('Enabled')
  })
})

describe('evidence CSV is safe to open in a spreadsheet', () => {
  it('neutralises cells that would otherwise evaluate as formulas', () => {
    const { stack } = testStack()
    const logs = new ServiceLogBucket(stack, '=cmd|calc', { bucketName: 'csv-logs' })
    new Bucket(stack, '@SUM', { serverAccessLogsBucket: logs.bucket })

    const csv = renderEvidenceCsv(buildAttestation(stack))
    const cells = csv
      .split('\n')
      .flatMap(line => line.split(','))
      .map(cell => cell.replace(/^"/, ''))

    expect(cells.filter(cell => /^[=+\-@\t\r]/.test(cell))).toEqual([])
  })
})

describe('verifyCompliance is free of side effects', () => {
  it('returns the same result and adds nothing to the tree when called repeatedly', () => {
    const { stack } = testStack()
    new LogGroup(stack, 'Lg')
    const before = stack.node.findAll().length

    const runs = [verifyCompliance(stack), verifyCompliance(stack), verifyCompliance(stack)]

    expect(new Set(runs.map(r => r.violations.length)).size).toBe(1)
    expect(stack.node.findAll().length).toBe(before)
  })
})

describe('ServiceLogBucket outstanding findings are all pinned', () => {
  /**
   * The class documented only S3DefaultEncryptionKMS for a while, which
   * understated what an assessor would see. All three are listed now.
   */
  it('has exactly the three findings its documentation names', () => {
    const { stack } = testStack()
    new ServiceLogBucket(stack, 'B', { bucketName: 'svc-logs' })

    expect(
      verifyCompliance(stack)
        .violations.map(v => v.ruleId)
        .sort()
    ).toEqual([
      'NIST.800.53.R5-S3BucketLoggingEnabled',
      'NIST.800.53.R5-S3BucketReplicationEnabled',
      'NIST.800.53.R5-S3DefaultEncryptionKMS',
    ])
  })
})
