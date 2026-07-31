import { App, type Stack } from 'aws-cdk-lib'
import { Match, Template } from 'aws-cdk-lib/assertions'

import { collectControlClaims } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { ConfigurationRecorder } from '../src/cmmc2/aws-config/index.js'
import { Detector } from '../src/cmmc2/aws-guardduty/index.js'
import { Hub } from '../src/cmmc2/aws-securityhub/index.js'
import { AccountBaseline, SecureBucket } from '../src/cmmc2/patterns/index.js'
import { CompliantStack } from '../src/cmmc2/index.js'
import { testStack } from './helpers/fixtures.js'

describe('Hub', () => {
  it('always enables NIST 800-53 Rev 5, plus the defaults', () => {
    const { stack } = testStack()
    new Hub(stack, 'Sh')

    const standards = Object.values(
      Template.fromStack(stack).findResources('AWS::SecurityHub::Standard')
    ).map(s => JSON.stringify((s.Properties as { StandardsArn: unknown }).StandardsArn))

    expect(standards).toHaveLength(3)
    expect(standards.join()).toContain('nist-800-53/v/5.0.0')
    expect(standards.join()).toContain('aws-foundational-security-best-practices')
    expect(standards.join()).toContain('cis-aws-foundations-benchmark/v/3.0.0')
  })

  it('still enables NIST 800-53 when asked for no additional standards', () => {
    const { stack } = testStack()
    new Hub(stack, 'Sh', { additionalStandards: [] })

    const template = Template.fromStack(stack)
    template.resourceCountIs('AWS::SecurityHub::Standard', 1)
    expect(
      JSON.stringify(Object.values(template.findResources('AWS::SecurityHub::Standard'))[0])
    ).toContain('nist-800-53')
  })

  /**
   * Hardcoding `arn:aws:` produces a template that fails at deploy in
   * GovCloud, which is exactly where this library's first users operate.
   */
  it('builds standard ARNs from the stack partition rather than hardcoding', () => {
    const app = new App()
    const stack = new CompliantStack(app, 'Gov', {
      env: { account: '111111111111', region: 'us-gov-west-1' },
      requiredTags: { project: 'p', owner: 'o', environment: 'e', containsCui: true },
    })
    new Hub(stack, 'Sh', { additionalStandards: [] })

    const arn = JSON.stringify(
      Object.values(Template.fromStack(stack).findResources('AWS::SecurityHub::Standard'))[0]
    )

    // Ref: AWS::Partition is better than a baked literal - it resolves
    // correctly in every partition, including for an environment-agnostic stack.
    expect(arn).toContain('AWS::Partition')
    expect(arn).toContain('us-gov-west-1')
  })

  it('consolidates findings and does not let AWS pick the standards', () => {
    const { stack } = testStack()
    new Hub(stack, 'Sh')

    Template.fromStack(stack).hasResourceProperties('AWS::SecurityHub::Hub', {
      EnableDefaultStandards: false,
      ControlFindingGenerator: 'SECURITY_CONTROL',
      AutoEnableControls: true,
    })
  })

  it('refuses a second hub in the same stack', () => {
    const { stack } = testStack()
    new Hub(stack, 'First')

    expect(() => new Hub(stack, 'Second')).toThrow(/one per account per region/)
  })
})

describe('Detector', () => {
  it('is enabled and publishes every fifteen minutes by default', () => {
    const { stack } = testStack()
    new Detector(stack, 'Gd')

    Template.fromStack(stack).hasResourceProperties('AWS::GuardDuty::Detector', {
      Enable: true,
      FindingPublishingFrequency: 'FIFTEEN_MINUTES',
    })
  })

  it('refuses a second detector in the same stack', () => {
    const { stack } = testStack()
    new Detector(stack, 'First')

    expect(() => new Detector(stack, 'Second')).toThrow(/one detector per account per region/)
  })
})

describe('ConfigurationRecorder', () => {
  function subject() {
    const { stack } = testStack()
    const bucket = new SecureBucket(stack, 'Audit', { bucketName: 'audit' })
    const recorder = new ConfigurationRecorder(stack, 'Cfg', { deliveryBucket: bucket.bucket })
    return { stack, recorder }
  }

  it('records every supported type including global resources', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::Config::ConfigurationRecorder', {
      RecordingGroup: { AllSupported: true, IncludeGlobalResourceTypes: true },
    })
  })

  it('delivers hourly snapshots by default', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::Config::DeliveryChannel', {
      ConfigSnapshotDeliveryProperties: { DeliveryFrequency: 'One_Hour' },
    })
  })

  /**
   * Without these statements the delivery channel is created, reports healthy,
   * and silently never writes - the worst failure mode there is for an audit
   * record.
   */
  it('adds the bucket policy statements AWS Config needs to deliver', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::S3::BucketPolicy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({ Sid: 'AWSConfigBucketPermissionsCheck' }),
          Match.objectLike({ Sid: 'AWSConfigBucketDelivery' }),
        ]),
      }),
    })
  })

  it('resolves the managed policy ARN per partition rather than baking one in', () => {
    const app = new App()
    const stack = new CompliantStack(app, 'Gov', {
      env: { account: '111111111111', region: 'us-gov-west-1' },
      requiredTags: { project: 'p', owner: 'o', environment: 'e', containsCui: true },
    })
    const bucket = new SecureBucket(stack, 'Audit', { bucketName: 'audit' })
    new ConfigurationRecorder(stack, 'Cfg', { deliveryBucket: bucket.bucket })

    expect(JSON.stringify(Template.fromStack(stack).findResources('AWS::IAM::Role'))).toContain(
      'AWS::Partition'
    )
  })

  it('refuses a second recorder in the same stack', () => {
    const { stack, recorder } = subject()
    void recorder

    expect(
      () =>
        new ConfigurationRecorder(stack, 'Second', {
          deliveryBucket: new SecureBucket(stack, 'Other', { bucketName: 'other' }).bucket,
        })
    ).toThrow(/one configuration recorder per account per region/)
  })
})

describe('AccountBaseline', () => {
  function subject() {
    const { stack } = testStack()
    const baseline = new AccountBaseline(stack, 'Baseline', { name: 'ferrum' })
    return { stack, baseline }
  }

  it('deploys all four detective services', () => {
    const { stack } = subject()
    const template = Template.fromStack(stack)

    template.resourceCountIs('AWS::CloudTrail::Trail', 1)
    template.resourceCountIs('AWS::Config::ConfigurationRecorder', 1)
    template.resourceCountIs('AWS::Config::DeliveryChannel', 1)
    template.resourceCountIs('AWS::SecurityHub::Hub', 1)
    template.resourceCountIs('AWS::GuardDuty::Detector', 1)
  })

  it('shares one audit bucket between the trail and Config', () => {
    const { stack } = subject()
    const template = Template.fromStack(stack)

    // The audit bucket and the access-log bucket SecureBucket creates for it.
    template.resourceCountIs('AWS::S3::Bucket', 2)
  })

  /**
   * These four are what move CA and RA off zero - no amount of correct
   * resource configuration answers "monitor controls on an ongoing basis".
   */
  it('claims against the domains resource configuration cannot reach', () => {
    const { baseline } = subject()
    const ids = new Set(collectControlClaims(baseline).map(c => c.claim.controlId))

    expect(ids.has('CA.L2-3.12.3')).toBe(true)
    expect(ids.has('CA.L2-3.12.1')).toBe(true)
    expect(ids.has('RA.L2-3.11.1')).toBe(true)
    expect(ids.has('RA.L2-3.11.2')).toBe(true)
    expect(ids.has('SI.L2-3.14.6')).toBe(true)
    expect(ids.has('SI.L2-3.14.7')).toBe(true)
  })

  it('never claims full satisfaction and always states a caveat', () => {
    const { baseline } = subject()

    for (const { claim } of collectControlClaims(baseline)) {
      expect(claim.satisfaction).not.toBe('full')
      expect(claim.caveat).toBeTruthy()
    }
  })

  it('rejects a non-lowercase name', () => {
    const { stack } = testStack()

    expect(() => new AccountBaseline(stack, 'B', { name: 'Ferrum' })).toThrow(/must be lowercase/)
  })

  /**
   * No Security Hub, GuardDuty or Config findings at all. The one non-S3
   * finding belongs to the role CDK creates inside cloudtrail.Trail for
   * CloudWatch delivery, which uses an inline policy we cannot reach without
   * reimplementing Trail.
   */
  it('leaves only the S3 opt-outs and the CDK Trail role finding', () => {
    const { stack } = subject()
    const ids = new Set(verifyCompliance(stack).violations.map(v => v.ruleId))

    expect([...ids].filter(id => !id.includes('S3')).sort()).toEqual([
      'NIST.800.53.R5-IAMNoInlinePolicy',
    ])
  })

  it('has no findings for the detective services themselves', () => {
    const { stack } = subject()
    const ids = verifyCompliance(stack).violations.map(v => v.ruleId)

    for (const service of ['SecurityHub', 'GuardDuty', 'Config', 'CloudTrail']) {
      expect(ids.filter(id => id.includes(service))).toEqual([])
    }
  })
})

describe('singleton guards are per-stack, not per-app', () => {
  it('allows one hub in each of two stacks', () => {
    const app = new App()
    const mk = (id: string): Stack =>
      new CompliantStack(app, id, {
        env: { account: '111111111111', region: 'us-east-1' },
        requiredTags: { project: 'p', owner: 'o', environment: 'e', containsCui: true },
      })

    expect(() => {
      new Hub(mk('A'), 'Sh')
      new Hub(mk('B'), 'Sh')
    }).not.toThrow()
  })
})
