import { RemovalPolicy } from 'aws-cdk-lib'
import { Match, Template } from 'aws-cdk-lib/assertions'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as kms from 'aws-cdk-lib/aws-kms'

import { collectControlClaims } from '../src/index.js'
import { FileSystem } from '../src/cmmc2/aws-efs/index.js'
import { PUBLIC_SUBNET_A, testStack } from './helpers/fixtures.js'

function subject() {
  const { stack, vpc } = testStack()
  const kmsKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })
  const fileSystem = new FileSystem(stack, 'Fs', {
    vpc,
    vpcSubnets: { subnets: vpc.privateSubnets },
    kmsKey,
  })
  return { stack, vpc, kmsKey, fileSystem }
}

describe('FileSystem synthesized properties', () => {
  it('encrypts at rest with the supplied customer-managed key', () => {
    const { stack, kmsKey } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::EFS::FileSystem', {
      Encrypted: true,
      KmsKeyId: stack.resolve(kmsKey.keyArn),
    })
  })

  it('enables automatic backups and denies anonymous access', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::EFS::FileSystem', {
      BackupPolicy: { Status: 'ENABLED' },
    })
    const fs = Template.fromStack(stack).findResources('AWS::EFS::FileSystem')
    const policy = Object.values(fs)[0]?.Properties?.FileSystemPolicy

    expect(JSON.stringify(policy)).not.toContain('elasticfilesystem:ClientMount*')
  })

  it('attaches a resource policy denying non-TLS access', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::EFS::FileSystem', {
      FileSystemPolicy: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Sid: 'DenyUnencryptedTransport',
            Effect: 'Deny',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          }),
        ]),
      }),
    })
  })

  it('defaults the removal policy to Retain', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResource('AWS::EFS::FileSystem', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
    })
  })

  it('honours RETAIN_ON_UPDATE_OR_DELETE, the only other policy EFS accepts', () => {
    const { stack, vpc } = testStack()
    const kmsKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })
    new FileSystem(stack, 'Fs', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      kmsKey,
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    })

    Template.fromStack(stack).hasResource('AWS::EFS::FileSystem', {
      DeletionPolicy: 'RetainExceptOnCreate',
    })
  })

  it('inherits the stack required tags', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::EFS::FileSystem', {
      FileSystemTags: Match.arrayWith([
        { Key: 'ContainsCui', Value: 'true' },
        { Key: 'Project', Value: 'vanguard' },
      ]),
    })
  })

  it('creates the same resources as the construct it wraps, so it can replace one in place', () => {
    const { stack } = subject()
    const template = Template.fromStack(stack)

    // Exactly one file system, two mount targets (one per private subnet), and
    // no extra resources smuggled in. A 1:1 wrapper that quietly created a
    // backup plan could not be dropped into an existing stack.
    template.resourceCountIs('AWS::EFS::FileSystem', 1)
    template.resourceCountIs('AWS::EFS::MountTarget', 2)
    template.resourceCountIs('AWS::Backup::BackupPlan', 0)
  })
})

describe('FileSystem subnet validation', () => {
  it('rejects SubnetType.PUBLIC', () => {
    const { stack, vpc } = testStack()
    const kmsKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })

    expect(
      () =>
        new FileSystem(stack, 'Fs', {
          vpc,
          vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
          kmsKey,
        })
    ).toThrow(/must not be placed in public subnets/)
  })

  it('rejects explicitly listed public subnets', () => {
    const { stack, vpc } = testStack()
    const kmsKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })

    expect(
      () =>
        new FileSystem(stack, 'Fs', {
          vpc,
          vpcSubnets: { subnets: vpc.publicSubnets },
          kmsKey,
        })
    ).toThrow(new RegExp(PUBLIC_SUBNET_A))
  })

  it('accepts private subnets', () => {
    expect(() => subject()).not.toThrow()
  })
})

describe('FileSystem control claims', () => {
  it('records claims against the practices it configures for', () => {
    const { fileSystem } = subject()
    const claims = collectControlClaims(fileSystem).map(c => c.claim)

    expect(claims.map(c => c.controlId).sort()).toEqual([
      'AC.L2-3.1.3',
      'MP.L2-3.8.9',
      'SC.L2-3.13.11',
      'SC.L2-3.13.16',
      'SC.L2-3.13.8',
    ])
    for (const claim of claims) expect(claim.frameworkRevision).toBe('rev2')
  })

  it('states a caveat on every claim, since none are satisfied outright', () => {
    const { fileSystem } = subject()

    for (const { claim } of collectControlClaims(fileSystem)) {
      expect(claim.satisfaction).not.toBe('full')
      expect(claim.caveat).toBeTruthy()
    }
  })

  it('does not claim MP.L2-3.8.9 without disclosing the missing backup plan', () => {
    const { fileSystem } = subject()
    const backupClaim = collectControlClaims(fileSystem).find(
      c => c.claim.controlId === 'MP.L2-3.8.9'
    )

    expect(backupClaim?.claim.caveat).toMatch(/not enrolled in an AWS Backup plan/)
  })
})
