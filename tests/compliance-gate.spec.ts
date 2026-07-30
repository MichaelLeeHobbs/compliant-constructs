import { Template } from 'aws-cdk-lib/assertions'
import * as efs from 'aws-cdk-lib/aws-efs'
import * as kms from 'aws-cdk-lib/aws-kms'

import { collectControlClaims, findUntaggableResources } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { FileSystem } from '../src/cmmc2/aws-efs/index.js'
import { EncryptedFileSystem } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

/**
 * The library's acceptance gate: constructs must satisfy cdk-nag's NIST
 * 800-53 Rev 5 pack without acknowledging anything away.
 *
 * This is deliberately an external check. Asserting our own synthesized
 * properties proves we wrote what we meant to write; running someone else's
 * rule pack proves what we wrote is actually the accepted configuration.
 */
describe('EncryptedFileSystem passes NIST 800-53 R5 with zero suppressions', () => {
  it('produces no violations', () => {
    const { stack, vpc } = testStack()
    new EncryptedFileSystem(stack, 'Storage', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      fileSystemName: 'vanguard-cui',
    })

    const result = verifyCompliance(stack)

    // Surface the rule IDs in the failure message; "expected true, got false"
    // would send whoever breaks this digging.
    expect(result.violations.map(v => `${v.ruleId} -> ${v.resources.join(', ')}`)).toEqual([])
    expect(result.compliant).toBe(true)
  })
})

/**
 * The 1:1 wrapper cannot satisfy EFSInBackupPlan on its own: that rule wants an
 * AWS::Backup::BackupSelection, and creating one would mean a drop-in wrapper
 * silently provisioning resources the construct it replaces does not.
 *
 * Pinning the exact outstanding set is the point. If a future cdk-nag adds an
 * EFS rule we do not satisfy, this fails and someone has to decide about it,
 * rather than the gap appearing only in a customer's audit.
 */
describe('FileSystem outstanding NIST 800-53 R5 findings', () => {
  it('has exactly one, and it is the backup plan enrolment', () => {
    const { stack, vpc } = testStack()
    const kmsKey = new kms.Key(stack, 'Key', { enableKeyRotation: true })
    new FileSystem(stack, 'Fs', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      kmsKey,
    })

    expect(verifyCompliance(stack).violations.map(v => v.ruleId)).toEqual([
      'NIST.800.53.R5-EFSInBackupPlan',
    ])
  })
})

/**
 * Claims cite cdk-nag rule IDs so the evidence report can reconcile against
 * cdk-nag's own view of the same resource. A typo there, or a rule cdk-nag
 * later renames, would silently break that join.
 *
 * A rule ID can only be observed when something violates it, so the reference
 * set comes from a deliberately non-compliant stack: unencrypted file system,
 * unrotated key, no backup plan. Those are exactly the rules our constructs
 * exist to satisfy, so they are exactly the ones we cite.
 */
describe('cited cdk-nag rule IDs are real', () => {
  function observableRuleIds(): Set<string> {
    const { stack, vpc } = testStack('NonCompliantStack')
    new efs.FileSystem(stack, 'PlainFs', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      encrypted: false,
    })
    new kms.Key(stack, 'UnrotatedKey', { enableKeyRotation: false })

    return new Set(verifyCompliance(stack).violations.map(v => v.ruleId))
  }

  function citedRuleIds(): Set<string> {
    const { stack, vpc } = testStack()
    new EncryptedFileSystem(stack, 'Storage', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      fileSystemName: 'vanguard-cui',
    })
    const key = new kms.Key(stack, 'Key', { enableKeyRotation: true })
    new FileSystem(stack, 'Fs', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      kmsKey: key,
    })

    return new Set(collectControlClaims(stack).flatMap(c => c.claim.nagRuleIds ?? []))
  }

  it('cites at least one rule per construct', () => {
    expect(citedRuleIds().size).toBeGreaterThanOrEqual(3)
  })

  it('every cited rule id is one the pack actually reports', () => {
    const observable = observableRuleIds()

    for (const ruleId of citedRuleIds()) {
      expect([ruleId, [...observable].sort()]).toEqual([ruleId, expect.arrayContaining([ruleId])])
    }
  })
})

describe('untaggable resources are reported rather than silently skipped', () => {
  it('lists EFS mount targets, which have no CloudFormation tags property', () => {
    const { stack, vpc } = testStack()
    new EncryptedFileSystem(stack, 'Storage', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      fileSystemName: 'vanguard-cui',
    })

    const untaggable = findUntaggableResources(stack)
    const types = new Set(untaggable.map(r => r.cfnType))

    expect(types.has('AWS::EFS::MountTarget')).toBe(true)
    // Everything reported must be a real resource with a real construct path.
    for (const r of untaggable) {
      expect(r.path).toContain(stack.node.id)
      expect(r.cfnType).toMatch(/^AWS::/)
    }
  })

  it('does not report resources that do carry the required tags', () => {
    const { stack, vpc } = testStack()
    new EncryptedFileSystem(stack, 'Storage', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      fileSystemName: 'vanguard-cui',
    })

    const untaggableTypes = new Set(findUntaggableResources(stack).map(r => r.cfnType))

    expect(untaggableTypes.has('AWS::EFS::FileSystem')).toBe(false)
    expect(untaggableTypes.has('AWS::KMS::Key')).toBe(false)
  })
})

describe('EncryptedFileSystem composition', () => {
  it('creates the backup plan, vault, key and security group around the file system', () => {
    const { stack, vpc } = testStack()
    new EncryptedFileSystem(stack, 'Storage', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      fileSystemName: 'vanguard-cui',
    })
    const template = Template.fromStack(stack)

    template.resourceCountIs('AWS::EFS::FileSystem', 1)
    template.resourceCountIs('AWS::KMS::Key', 1)
    template.resourceCountIs('AWS::Backup::BackupPlan', 1)
    template.resourceCountIs('AWS::Backup::BackupVault', 1)
    template.resourceCountIs('AWS::Backup::BackupSelection', 1)
    template.resourceCountIs('AWS::EC2::SecurityGroup', 1)
  })

  it('rejects a non-lowercase file system name', () => {
    const { stack, vpc } = testStack()

    expect(
      () =>
        new EncryptedFileSystem(stack, 'Storage', {
          vpc,
          vpcSubnets: { subnets: vpc.privateSubnets },
          fileSystemName: 'Vanguard-CUI',
        })
    ).toThrow(/must be lowercase/)
  })
})
