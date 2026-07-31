import { Match, Template } from 'aws-cdk-lib/assertions'
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb'
import * as lambda from 'aws-cdk-lib/aws-lambda'

import { collectControlClaims } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { Table } from '../src/cmmc2/aws-dynamodb/index.js'
import { Queue } from '../src/cmmc2/aws-sqs/index.js'
import { Topic } from '../src/cmmc2/aws-sns/index.js'
import { LogGroup } from '../src/cmmc2/aws-logs/index.js'
import { Function } from '../src/cmmc2/aws-lambda/index.js'
import { SecureFunction } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

const CODE = lambda.Code.fromInline('exports.handler = async () => {}')

describe('Queue', () => {
  it('encrypts with the stack key and enforces TLS', () => {
    const { stack } = testStack()
    new Queue(stack, 'Q')
    const template = Template.fromStack(stack)

    template.hasResourceProperties('AWS::SQS::Queue', { KmsMasterKeyId: Match.anyValue() })
    template.hasResourceProperties('AWS::SQS::QueuePolicy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Deny',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          }),
        ]),
      }),
    })
  })

  it('creates no dead-letter queue, staying 1:1 with the construct it wraps', () => {
    const { stack } = testStack()
    new Queue(stack, 'Q')

    Template.fromStack(stack).resourceCountIs('AWS::SQS::Queue', 1)
  })

  it('passes the NIST pack', () => {
    const { stack } = testStack()
    new Queue(stack, 'Q')

    expect(verifyCompliance(stack).violations).toEqual([])
  })
})

describe('Topic', () => {
  it('encrypts with the stack key and enforces TLS publishing', () => {
    const { stack } = testStack()
    new Topic(stack, 'T')
    const template = Template.fromStack(stack)

    template.hasResourceProperties('AWS::SNS::Topic', { KmsMasterKeyId: Match.anyValue() })
    template.hasResourceProperties('AWS::SNS::TopicPolicy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Deny',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          }),
        ]),
      }),
    })
  })

  it('passes the NIST pack', () => {
    const { stack } = testStack()
    new Topic(stack, 'T')

    expect(verifyCompliance(stack).violations).toEqual([])
  })
})

describe('Table', () => {
  const partitionKey = { name: 'pk', type: dynamodb.AttributeType.STRING }

  it('encrypts with a customer-managed key', () => {
    const { stack } = testStack()
    new Table(stack, 'T', { partitionKey })

    Template.fromStack(stack).hasResourceProperties('AWS::DynamoDB::GlobalTable', {
      SSESpecification: Match.objectLike({ SSEEnabled: true }),
    })
  })

  /**
   * Mandated even though the R5 pack does not check for it. A table is often
   * the only copy of what it holds, and PITR is the only thing between a bad
   * write and permanent loss.
   */
  it('enables point-in-time recovery with the maximum window by default', () => {
    const { stack } = testStack()
    new Table(stack, 'T', { partitionKey })

    Template.fromStack(stack).hasResourceProperties('AWS::DynamoDB::GlobalTable', {
      Replicas: Match.arrayWith([
        Match.objectLike({
          PointInTimeRecoverySpecification: {
            PointInTimeRecoveryEnabled: true,
            RecoveryPeriodInDays: 35,
          },
        }),
      ]),
    })
  })

  it('retains through a stack teardown', () => {
    const { stack } = testStack()
    new Table(stack, 'T', { partitionKey })

    Template.fromStack(stack).hasResource('AWS::DynamoDB::GlobalTable', {
      DeletionPolicy: 'Retain',
    })
  })

  it('records the configured recovery window in its claim', () => {
    const { stack } = testStack()
    const table = new Table(stack, 'T', { partitionKey, recoveryPeriodInDays: 7 })
    const claim = collectControlClaims(table).find(c => c.claim.controlId === 'MP.L2-3.8.9')

    expect(claim?.claim.evidence).toContain('7-day window')
  })

  it('passes the NIST pack', () => {
    const { stack } = testStack()
    new Table(stack, 'T', { partitionKey })

    expect(verifyCompliance(stack).violations).toEqual([])
  })
})

describe('Function', () => {
  function subject() {
    const { stack } = testStack()
    const logGroup = new LogGroup(stack, 'Logs')
    const fn = new Function(stack, 'Fn', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: CODE,
      logGroup,
    })
    return { stack, fn, logGroup }
  }

  it('encrypts environment variables and enables tracing', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::Lambda::Function', {
      KmsKeyArn: Match.anyValue(),
      TracingConfig: { Mode: 'Active' },
    })
  })

  /**
   * The log group Lambda creates for itself never appears in the template, so
   * it is never tagged, encrypted or retention-bounded. Requiring an explicit
   * one is the only way to bring it inside the scope boundary.
   */
  it('writes to the supplied log group', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::Lambda::Function', {
      LoggingConfig: Match.objectLike({ LogGroup: Match.anyValue() }),
    })
  })

  // One structural (the CDK-generated role's inline policy) and three
  // contextual, each of which clears when the caller supplies the relevant prop.
  it('pins its four outstanding findings', () => {
    const { stack } = subject()

    expect(
      verifyCompliance(stack)
        .violations.map(v => v.ruleId)
        .sort()
    ).toEqual([
      'NIST.800.53.R5-IAMNoInlinePolicy',
      'NIST.800.53.R5-LambdaConcurrency',
      'NIST.800.53.R5-LambdaDLQ',
      'NIST.800.53.R5-LambdaInsideVPC',
    ])
  })
})

describe('SecureFunction', () => {
  function subject() {
    const { stack } = testStack()
    const secure = new SecureFunction(stack, 'Fn', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: CODE,
    })
    return { stack, secure }
  }

  it('creates the log group the wrapper requires', () => {
    const { stack, secure } = subject()

    expect(secure.logGroup).toBeDefined()
    Template.fromStack(stack).resourceCountIs('AWS::Logs::LogGroup', 1)
  })

  it('encrypts that log group with the stack key', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::Logs::LogGroup', {
      KmsKeyId: Match.anyValue(),
      RetentionInDays: 365,
    })
  })

  it('creates a dead-letter queue, clearing LambdaDLQ', () => {
    const { stack, secure } = subject()

    expect(secure.deadLetterQueue).toBeDefined()
    expect(verifyCompliance(stack).violations.map(v => v.ruleId)).not.toContain(
      'NIST.800.53.R5-LambdaDLQ'
    )
  })

  it('leaves only the contextual and structural findings', () => {
    const { stack } = subject()

    // VPC placement and reserved concurrency are decisions this pattern should
    // not make for you; the inline policy is the CDK's generated role.
    expect(
      verifyCompliance(stack)
        .violations.map(v => v.ruleId)
        .sort()
    ).toEqual([
      'NIST.800.53.R5-IAMNoInlinePolicy',
      'NIST.800.53.R5-LambdaConcurrency',
      'NIST.800.53.R5-LambdaInsideVPC',
    ])
  })
})

describe('claims', () => {
  it('never claim full satisfaction and always state a caveat', () => {
    const { stack } = testStack()
    new Queue(stack, 'Q')
    new Topic(stack, 'T')
    new Table(stack, 'D', { partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING } })

    const claims = collectControlClaims(stack).map(c => c.claim)

    expect(claims.length).toBeGreaterThan(0)
    for (const claim of claims) {
      expect(claim.satisfaction).not.toBe('full')
      expect(claim.caveat).toBeTruthy()
    }
  })
})
