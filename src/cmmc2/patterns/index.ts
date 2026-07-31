import { RemovalPolicy } from 'aws-cdk-lib'
import * as backup from 'aws-cdk-lib/aws-backup'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import type * as efs from 'aws-cdk-lib/aws-efs'
import type * as kms from 'aws-cdk-lib/aws-kms'
import { Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { FileSystem } from '../aws-efs/index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export interface EncryptedFileSystemProps {
  readonly vpc: ec2.IVpc

  /** Subnets for the mount targets. Must not be public. */
  readonly vpcSubnets: ec2.SubnetSelection

  /** Name for the file system. Must be lowercase. */
  readonly fileSystemName: string

  /**
   * Key for the file system and its backup vault.
   *
   * Defaults to the stack's key. Pass one to give this file system a key with
   * its own lifetime.
   */
  readonly encryptionKey?: kms.IKey

  /** Defaults to `RETAIN`. */
  readonly removalPolicy?: NonDestructiveRemovalPolicy

  /**
   * Existing backup plan to enrol the file system into.
   *
   * Defaults to a plan created here with 35-day retention, writing to a vault
   * encrypted with this construct's own key.
   */
  readonly backupPlan?: backup.BackupPlan

  /** When set, an access point is created with these options. */
  readonly accessPoint?: efs.AccessPointOptions
}

/**
 * An EFS file system with everything a CMMC Level 2 deployment needs around it.
 *
 * Where {@link FileSystem} is a 1:1 wrapper that creates exactly what
 * `efs.FileSystem` creates, this composes the pieces that a compliant
 * deployment needs but that a file system cannot provide for itself: a
 * customer-managed key with rotation, a default-deny security group, and
 * enrolment in an AWS Backup plan writing to an encrypted vault.
 *
 * That last piece is why this exists. `efs.FileSystem`'s `enableAutomaticBackups`
 * sets EFS's own backup policy, which is not the same as an AWS Backup plan and
 * does not give you governed retention. It is also the one thing standing
 * between the 1:1 wrapper and a clean cdk-nag run.
 *
 * Because this creates a subtree, adopting it changes construct paths. It is
 * for new stacks; retrofitting an existing file system would replace it.
 */
export class EncryptedFileSystem extends Construct {
  readonly fileSystem: FileSystem
  readonly encryptionKey: kms.IKey
  readonly securityGroup: ec2.SecurityGroup
  readonly backupPlan: backup.BackupPlan
  readonly accessPoint?: efs.AccessPoint

  constructor(scope: Construct, id: string, props: EncryptedFileSystemProps) {
    super(scope, id)

    if (props.fileSystemName !== props.fileSystemName.toLowerCase()) {
      throw new Error(`fileSystemName must be lowercase, got "${props.fileSystemName}"`)
    }

    const removalPolicy = props.removalPolicy ?? RemovalPolicy.RETAIN

    // Defaults to the stack key rather than minting one per file system: the
    // point of a stack-scoped key is that the cryptographic boundary matches
    // the assessment boundary, and a pattern quietly creating its own would
    // undo that.
    this.encryptionKey = resolveEncryptionKey(scope, props.encryptionKey)

    // Default-deny egress. The CDK's default is allowAllOutbound: true, which
    // is the opposite of what SC.L2-3.13.6 asks for.
    this.securityGroup = new ec2.SecurityGroup(this, 'SecurityGroup', {
      vpc: props.vpc,
      description: `Mount target access for EFS ${props.fileSystemName}`,
      allowAllOutbound: false,
    })

    this.fileSystem = new FileSystem(this, 'FileSystem', {
      vpc: props.vpc,
      vpcSubnets: props.vpcSubnets,
      securityGroup: this.securityGroup,
      fileSystemName: props.fileSystemName,
      kmsKey: this.encryptionKey,
      removalPolicy,
    })

    if (props.accessPoint !== undefined) {
      this.accessPoint = this.fileSystem.addAccessPoint('AccessPoint', props.accessPoint)
    }

    this.backupPlan = props.backupPlan ?? this.createBackupPlan(props.fileSystemName, removalPolicy)
    this.backupPlan.addSelection('BackupSelection', {
      resources: [backup.BackupResource.fromEfsFileSystem(this.fileSystem)],
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'MP.L2-3.8.9',
        satisfaction: 'partial',
        evidence:
          'Enrolled in an AWS Backup plan with 35-day retention, writing to a vault encrypted ' +
          'with a customer-managed KMS key',
        nagRuleIds: ['NIST.800.53.R5-EFSInBackupPlan'],
        caveat:
          'Evidences that backups exist, are retained, and are encrypted. Does not evidence ' +
          'restore testing or off-site handling procedures.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.6',
        satisfaction: 'partial',
        evidence: 'Mount target security group created with allowAllOutbound=false',
        caveat:
          'Establishes deny-by-default at this security group only. Ingress rules added by ' +
          'the caller, and any other path into the subnet, are out of scope.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.11',
        satisfaction: 'supporting',
        evidence: 'Customer-managed KMS key with automatic annual rotation enabled',
        nagRuleIds: ['NIST.800.53.R5-KMSBackingKeyRotationEnabled'],
        caveat:
          'FIPS validation depends on the region and endpoints in use, which this construct ' +
          'does not control.',
      }),
    ])
  }

  private createBackupPlan(name: string, removalPolicy: RemovalPolicy): backup.BackupPlan {
    const vault = new backup.BackupVault(this, 'BackupVault', {
      backupVaultName: `${name}-efs-vault`,
      encryptionKey: this.encryptionKey,
      removalPolicy,
    })

    return backup.BackupPlan.daily35DayRetention(this, 'BackupPlan', vault)
  }
}

export { SecureBucket, type SecureBucketProps } from "./secure-bucket.js"
export {
  EncryptedDatabaseInstance,
  type EncryptedDatabaseInstanceProps,
} from "./encrypted-database.js"

export { SecureFunction, type SecureFunctionProps } from "./secure-function.js"
