import { Match, Template } from 'aws-cdk-lib/assertions'

import { collectControlClaims } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { Trail } from '../src/cmmc2/aws-cloudtrail/index.js'
import { ApplicationLoadBalancer } from '../src/cmmc2/aws-elasticloadbalancingv2/index.js'
import { LogGroup } from '../src/cmmc2/aws-logs/index.js'
import { SecureBucket, ServiceLogBucket } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

describe('ServiceLogBucket', () => {
  /**
   * The one bucket in the library that does not use a customer-managed key.
   * ELB cannot deliver access logs to a KMS-encrypted bucket - the CDK rejects
   * the combination - so this is an AWS constraint, not a choice.
   */
  it('uses SSE-S3, because service log delivery cannot use KMS', () => {
    const { stack } = testStack()
    new ServiceLogBucket(stack, 'Logs', { bucketName: 'svc-logs' })

    Template.fromStack(stack).hasResourceProperties('AWS::S3::Bucket', {
      BucketEncryption: {
        ServerSideEncryptionConfiguration: [
          Match.objectLike({ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }),
        ],
      },
    })
  })

  it('still blocks public access, enforces TLS and versions', () => {
    const { stack } = testStack()
    new ServiceLogBucket(stack, 'Logs', { bucketName: 'svc-logs' })

    Template.fromStack(stack).hasResourceProperties('AWS::S3::Bucket', {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
      VersioningConfiguration: { Status: 'Enabled' },
    })
  })

  it('says in its claim that key custody sits with AWS', () => {
    const { stack } = testStack()
    const bucket = new ServiceLogBucket(stack, 'Logs', { bucketName: 'svc-logs' })
    const claim = collectControlClaims(bucket).find(c => c.claim.controlId === 'AU.L2-3.3.8')

    expect(claim?.claim.caveat).toMatch(/key custody for these records therefore sits with AWS/i)
  })

  it('rejects a non-lowercase name', () => {
    const { stack } = testStack()

    expect(() => new ServiceLogBucket(stack, 'L', { bucketName: 'Svc-Logs' })).toThrow(
      /must be lowercase/
    )
  })
})

describe('ApplicationLoadBalancer', () => {
  function subject() {
    const { stack, vpc } = testStack()
    const logs = new ServiceLogBucket(stack, 'AlbLogs', { bucketName: 'alb-logs' })
    const alb = new ApplicationLoadBalancer(stack, 'Alb', {
      vpc,
      internetFacing: false,
      accessLogsBucket: logs.bucket,
    })
    return { stack, alb }
  }

  it('enables deletion protection, access logs and invalid header dropping', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
      LoadBalancerAttributes: Match.arrayWith([
        { Key: 'deletion_protection.enabled', Value: 'true' },
        { Key: 'routing.http.drop_invalid_header_fields.enabled', Value: 'true' },
        { Key: 'access_logs.s3.enabled', Value: 'true' },
      ]),
    })
  })

  it('refuses a KMS-encrypted access log bucket, as ELB cannot deliver to one', () => {
    const { stack, vpc } = testStack()
    const kmsBucket = new SecureBucket(stack, 'KmsLogs', { bucketName: 'kms-logs' })

    expect(
      () =>
        new ApplicationLoadBalancer(stack, 'Alb', {
          vpc,
          internetFacing: false,
          accessLogsBucket: kmsBucket.bucket,
        })
    ).toThrow(/Bucket encryption using KMS keys is unsupported/)
  })

  /**
   * A WAF web ACL is a real decision with a real bill, and the right rule set
   * depends on what sits behind the load balancer.
   */
  it('leaves only the WAF finding outstanding', () => {
    const { stack } = subject()
    const albFindings = verifyCompliance(stack)
      .violations.map(v => v.ruleId)
      .filter(id => id.includes('ALB') || id.includes('ELB'))

    expect(albFindings).toEqual(['NIST.800.53.R5-ALBWAFEnabled'])
  })
})

describe('Trail', () => {
  function subject() {
    const { stack } = testStack()
    const bucket = new SecureBucket(stack, 'TrailBucket', { bucketName: 'trail-logs' })
    const logGroup = new LogGroup(stack, 'TrailLogs')
    const trail = new Trail(stack, 'Trail', {
      bucket: bucket.bucket,
      cloudWatchLogGroup: logGroup,
    })
    return { stack, trail }
  }

  it('is multi-region, validated, and delivered to CloudWatch', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::CloudTrail::Trail', {
      IsMultiRegionTrail: true,
      IncludeGlobalServiceEvents: true,
      EnableLogFileValidation: true,
      KMSKeyId: Match.anyValue(),
      CloudWatchLogsLogGroupArn: Match.anyValue(),
    })
  })

  it('claims against the three audit practices it evidences', () => {
    const { trail } = subject()
    const ids = collectControlClaims(trail)
      .map(c => c.claim.controlId)
      .sort()

    expect(ids).toEqual(['AU.L2-3.3.1', 'AU.L2-3.3.2', 'AU.L2-3.3.8'])
  })

  it('is honest that digests detect tampering rather than prevent it', () => {
    const { trail } = subject()
    const claim = collectControlClaims(trail).find(c => c.claim.controlId === 'AU.L2-3.3.8')

    expect(claim?.claim.caveat).toMatch(/Object Lock/)
  })

  it('has no CloudTrail-specific findings outstanding', () => {
    const { stack } = subject()
    const trailFindings = verifyCompliance(stack)
      .violations.map(v => v.ruleId)
      .filter(id => id.includes('CloudTrail'))

    expect(trailFindings).toEqual([])
  })
})
