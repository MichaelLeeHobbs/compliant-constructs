import { App, Stack } from 'aws-cdk-lib'
import { Template } from 'aws-cdk-lib/assertions'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as kms from 'aws-cdk-lib/aws-kms'
import * as s3 from 'aws-cdk-lib/aws-s3'

import { CompliantStack, DEFAULT_ENCRYPTION_KEY_ID } from '../src/cmmc2/index.js'
import { FileSystem } from '../src/cmmc2/aws-efs/index.js'
import { Bucket } from '../src/cmmc2/aws-s3/index.js'
import { EncryptedFileSystem } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

const TAGS = {
  project: 'vanguard',
  owner: 'platform',
  environment: 'prod',
  containsCui: true,
} as const

describe('CompliantStack default encryption key', () => {
  it('is not created when nothing asks for one', () => {
    const stack = new CompliantStack(new App(), 'Empty', { requiredTags: TAGS })

    // A stack with no encrypted resources should not provision a key nobody
    // uses - hence the lazy getter rather than eager creation in the ctor.
    Template.fromStack(stack).resourceCountIs('AWS::KMS::Key', 0)
  })

  it('is created on first use, with rotation and a retaining policy', () => {
    const stack = new CompliantStack(new App(), 'Used', { requiredTags: TAGS })
    void stack.encryptionKey

    const template = Template.fromStack(stack)
    template.resourceCountIs('AWS::KMS::Key', 1)
    template.hasResourceProperties('AWS::KMS::Key', { EnableKeyRotation: true })
    template.hasResource('AWS::KMS::Key', { DeletionPolicy: 'Retain' })
  })

  it('returns the same key on repeated access', () => {
    const stack = new CompliantStack(new App(), 'Memoized', { requiredTags: TAGS })

    expect(stack.encryptionKey).toBe(stack.encryptionKey)
    Template.fromStack(stack).resourceCountIs('AWS::KMS::Key', 1)
  })

  it('uses a supplied key instead of creating one', () => {
    const app = new App()
    const keyStack = new Stack(app, 'Keys')
    const existing = new kms.Key(keyStack, 'Shared', { enableKeyRotation: true })
    const stack = new CompliantStack(app, 'Consumer', {
      requiredTags: TAGS,
      encryptionKey: existing,
    })

    expect(stack.encryptionKey).toBe(existing)
    expect(stack.node.tryFindChild(DEFAULT_ENCRYPTION_KEY_ID)).toBeUndefined()
    Template.fromStack(stack).resourceCountIs('AWS::KMS::Key', 0)
  })
})

describe('constructs resolving the stack key', () => {
  it('share one key across every construct that does not bring its own', () => {
    const { stack, vpc } = testStack()
    const vpcSubnets = { subnets: vpc.privateSubnets }

    new FileSystem(stack, 'Fs', { vpc, vpcSubnets })
    new EncryptedFileSystem(stack, 'Cui', { vpc, vpcSubnets, fileSystemName: 'cui' })
    new Bucket(stack, 'Data', {
      serverAccessLogsBucket: new s3.Bucket(stack, 'Logs', {
        encryption: s3.BucketEncryption.KMS_MANAGED,
      }),
    })

    // Three constructs, one key. This is the whole point: the cryptographic
    // boundary matches the stack-level assessment boundary.
    Template.fromStack(stack).resourceCountIs('AWS::KMS::Key', 1)
  })

  it('honours a per-resource override without disturbing the stack key', () => {
    const { stack, vpc } = testStack()
    const dedicated = new kms.Key(stack, 'Dedicated', { enableKeyRotation: true })

    new FileSystem(stack, 'Shared', { vpc, vpcSubnets: { subnets: vpc.privateSubnets } })
    new FileSystem(stack, 'Isolated', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      kmsKey: dedicated,
    })

    const template = Template.fromStack(stack)
    // The dedicated key plus the stack default.
    template.resourceCountIs('AWS::KMS::Key', 2)

    const fileSystems = Object.values(template.findResources('AWS::EFS::FileSystem'))
    const keyIds = fileSystems.map(fs => JSON.stringify(fs.Properties?.KmsKeyId))

    expect(new Set(keyIds).size).toBe(2)
  })

  it('does not create a key when every construct supplies its own', () => {
    const { stack, vpc } = testStack()
    const own = new kms.Key(stack, 'Own', { enableKeyRotation: true })

    new FileSystem(stack, 'Fs', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      kmsKey: own,
    })

    expect(stack.node.tryFindChild(DEFAULT_ENCRYPTION_KEY_ID)).toBeUndefined()
    Template.fromStack(stack).resourceCountIs('AWS::KMS::Key', 1)
  })
})

describe('using a compliant construct outside a CompliantStack', () => {
  function plainStack() {
    const app = new App()
    const stack = new Stack(app, 'PlainStack', {
      env: { account: '111111111111', region: 'us-east-1' },
    })
    const vpc = ec2.Vpc.fromVpcAttributes(stack, 'Vpc', {
      vpcId: 'vpc-0aa11bb22cc33dd44',
      availabilityZones: ['us-east-1a'],
      privateSubnetIds: ['subnet-0aa11bb22cc33dd01'],
      privateSubnetRouteTableIds: ['rtb-0aa11bb22cc33dd01'],
    })
    return { stack, vpc }
  }

  it('throws rather than silently inventing a key', () => {
    const { stack, vpc } = plainStack()

    expect(
      () => new FileSystem(stack, 'Fs', { vpc, vpcSubnets: { subnets: vpc.privateSubnets } })
    ).toThrow(/is a plain cdk.Stack/)
  })

  it('names the construct and suggests both remedies', () => {
    const { stack, vpc } = plainStack()

    expect(
      () => new FileSystem(stack, 'Fs', { vpc, vpcSubnets: { subnets: vpc.privateSubnets } })
    ).toThrow(/use CompliantStack.*or pass an encryption key/s)
  })

  it('works in a plain stack when a key is supplied explicitly', () => {
    const { stack, vpc } = plainStack()
    const key = new kms.Key(stack, 'Key', { enableKeyRotation: true })

    expect(
      () =>
        new FileSystem(stack, 'Fs', {
          vpc,
          vpcSubnets: { subnets: vpc.privateSubnets },
          kmsKey: key,
        })
    ).not.toThrow()
  })
})
