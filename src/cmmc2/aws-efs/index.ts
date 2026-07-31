import { RemovalPolicy } from 'aws-cdk-lib'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as efs from 'aws-cdk-lib/aws-efs'
import * as iam from 'aws-cdk-lib/aws-iam'
import type * as kms from 'aws-cdk-lib/aws-kms'
import { type Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

/**
 * Props this wrapper takes ownership of, and therefore removes from the
 * caller's reach entirely.
 *
 * Listing them as a named type rather than inline in the `Omit` gives us the
 * drift canary below: if AWS renames or removes one of these, the assignment
 * stops compiling instead of the `Omit` silently becoming a no-op and shipping
 * an unencrypted file system.
 */
type MandatedProps =
  | 'encrypted'
  | 'kmsKey'
  | 'allowAnonymousAccess'
  | 'enableAutomaticBackups'
  | 'fileSystemPolicy'
  | 'removalPolicy'
  | 'vpcSubnets'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof efs.FileSystemProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface FileSystemProps extends Omit<efs.FileSystemProps, MandatedProps> {
  /**
   * Customer-managed KMS key used to encrypt the file system.
   *
   * Required, where the CDK makes it optional. Encryption at rest with an
   * AWS-managed key leaves key custody with AWS, which is weaker evidence for
   * SC.L2-3.13.16 than a key whose policy and rotation you control.
   */
  readonly kmsKey?: kms.IKey

  /**
   * Subnets for the mount targets. Required, and must not be public.
   *
   * The CDK defaults to all private subnets, which is usually right - but
   * "usually right by default" is not the same as "stated", and a mount target
   * in a public subnet is not something to discover after the fact.
   */
  readonly vpcSubnets: ec2.SubnetSelection

  /**
   * Defaults to `RETAIN`. `DESTROY` is not representable: tearing down a stack
   * should not be able to delete CUI as a side effect.
   */
  readonly removalPolicy?: NonDestructiveRemovalPolicy
}

/**
 * An EFS file system configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `efs.FileSystem`: same constructor shape, same
 * methods, same interfaces. What differs is that the compliant configuration
 * is applied unconditionally and the non-compliant one cannot be expressed.
 *
 * Encryption with a customer-managed key, automatic backups, and a resource
 * policy denying non-TLS access are all mandated. Anonymous access is off.
 * Removal policy cannot be `DESTROY`.
 *
 * This construct creates exactly the resources `efs.FileSystem` does, so it can
 * replace one in an existing stack without changing construct paths. It does
 * not enrol the file system in an AWS Backup plan - that would create resources
 * a 1:1 wrapper has no business creating. Use `EncryptedFileSystem` from
 * `cmmc2/patterns` for that, or add a `BackupSelection` yourself.
 */
export class FileSystem extends efs.FileSystem {
  constructor(scope: Construct, id: string, props: FileSystemProps) {
    assertSubnetsAreNotPublic(props.vpc, props.vpcSubnets)

    const kmsKey = resolveEncryptionKey(scope, props.kmsKey)

    super(scope, id, {
      ...props,
      encrypted: true,
      kmsKey,
      allowAnonymousAccess: false,
      enableAutomaticBackups: true,
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    })

    // Belt and braces alongside `encrypted: true`: the property governs data at
    // rest, this governs the wire. Without it, a client can mount without TLS.
    this.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'DenyUnencryptedTransport',
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['*'],
        conditions: { Bool: { 'aws:SecureTransport': 'false' } },
      })
    )

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Encrypted=true with a customer-managed KMS key',
        nagRuleIds: ['NIST.800.53.R5-EFSEncrypted'],
        caveat:
          'Evidences encryption at rest only. Key custody, rotation policy and access ' +
          'authorisation are properties of the KMS key and its policy, not of this file system.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.8',
        satisfaction: 'partial',
        evidence: 'Resource policy denies all actions where aws:SecureTransport is false',
        caveat:
          'Enforces TLS at the file system. Does not evidence that clients mount with the ' +
          'TLS option, nor protect CUI in transit anywhere else in the system.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.11',
        satisfaction: 'supporting',
        evidence: 'Encryption performed by AWS KMS using a customer-managed key',
        caveat:
          'Whether the cryptography is FIPS-validated depends on the region and the endpoints ' +
          'in use, neither of which this construct controls. Evidence only.',
      }),
      cmmc2Claim({
        practice: 'MP.L2-3.8.9',
        satisfaction: 'partial',
        evidence: 'BackupPolicy=ENABLED, backups encrypted with the same customer-managed key',
        caveat:
          'EFS automatic backups only. The file system is not enrolled in an AWS Backup plan, ' +
          'so retention and lifecycle are not governed here - see EncryptedFileSystem.',
      }),
      cmmc2Claim({
        practice: 'AC.L2-3.1.3',
        satisfaction: 'supporting',
        evidence: 'AllowAnonymousAccess=false; access mediated by mount targets in private subnets',
        caveat:
          'Flow control depends primarily on the security groups and network ACLs governing ' +
          'the mount targets, which are supplied by the caller.',
      }),
    ])
  }
}

/**
 * Reject a subnet selection that resolves to public subnets.
 *
 * This is the runtime half of the design: `SubnetSelection` is a structural
 * type with no notion of "not public", so the type system cannot express it and
 * a constructor check has to.
 */
function assertSubnetsAreNotPublic(vpc: ec2.IVpc, selection: ec2.SubnetSelection): void {
  if (selection.subnetType === ec2.SubnetType.PUBLIC) {
    throw new Error(
      'EFS mount targets must not be placed in public subnets: ' +
        'vpcSubnets.subnetType is SubnetType.PUBLIC'
    )
  }

  if (selection.subnets === undefined) return

  const publicIds = new Set(vpc.publicSubnets.map(s => s.subnetId))
  const offenders = selection.subnets.filter(s => publicIds.has(s.subnetId))

  if (offenders.length > 0) {
    throw new Error(
      'EFS mount targets must not be placed in public subnets: ' +
        `vpcSubnets.subnets includes ${offenders.map(s => s.subnetId).join(', ')}`
    )
  }
}

export { type NonDestructiveRemovalPolicy } from '../../index.js'
