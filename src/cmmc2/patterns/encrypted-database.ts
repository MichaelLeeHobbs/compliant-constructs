import { RemovalPolicy } from 'aws-cdk-lib'
import * as backup from 'aws-cdk-lib/aws-backup'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as kms from 'aws-cdk-lib/aws-kms'
import type * as rds from 'aws-cdk-lib/aws-rds'
import { Construct } from 'constructs'

import { addControlClaims, type SnapshottableRemovalPolicy } from '../../index.js'
import { DatabaseInstance } from '../aws-rds/index.js'
import { cmmc2Claim } from '../index.js'

export interface EncryptedDatabaseInstanceProps {
  readonly vpc: ec2.IVpc

  /** Subnets for the instance. Should be private or isolated. */
  readonly vpcSubnets: ec2.SubnetSelection

  /** Database name and identifier stem. Must be lowercase. */
  readonly databaseName: string

  readonly engine: rds.IInstanceEngine
  readonly instanceType: ec2.InstanceType

  /** Master username. Credentials are always a generated, CMK-encrypted secret. */
  readonly masterUsername?: string

  /** Defaults to `RETAIN`. */
  readonly removalPolicy?: SnapshottableRemovalPolicy

  /** Existing backup plan to enrol into. Defaults to one created here. */
  readonly backupPlan?: backup.BackupPlan
}

/**
 * An RDS instance with the key, network isolation and backup plan around it.
 *
 * Mirrors `EncryptedFileSystem`: a rotating customer-managed key, a
 * default-deny security group, and enrolment in an AWS Backup plan writing to
 * an encrypted vault. That last part is what clears `RDSInBackupPlan`, which
 * RDS automated backups do not - the rule wants an
 * `AWS::Backup::BackupSelection`, and the RDS backup window is a different
 * feature with different retention semantics.
 *
 * Two cdk-nag findings remain, both false positives from the credential
 * rotation Lambda's security group rule. See {@link DatabaseInstance}.
 */
export class EncryptedDatabaseInstance extends Construct {
  readonly instance: DatabaseInstance
  readonly kmsKey: kms.Key
  readonly securityGroup: ec2.SecurityGroup
  readonly backupPlan: backup.BackupPlan

  constructor(scope: Construct, id: string, props: EncryptedDatabaseInstanceProps) {
    super(scope, id)

    if (props.databaseName !== props.databaseName.toLowerCase()) {
      throw new Error(`databaseName must be lowercase, got "${props.databaseName}"`)
    }

    const removalPolicy = props.removalPolicy ?? RemovalPolicy.RETAIN

    this.kmsKey = new kms.Key(this, 'Key', {
      description: `CUI encryption key for database ${props.databaseName}`,
      enableKeyRotation: true,
      removalPolicy,
    })

    this.securityGroup = new ec2.SecurityGroup(this, 'SecurityGroup', {
      vpc: props.vpc,
      description: `Database access for ${props.databaseName}`,
      allowAllOutbound: false,
    })

    this.instance = new DatabaseInstance(this, 'Instance', {
      vpc: props.vpc,
      vpcSubnets: props.vpcSubnets,
      securityGroups: [this.securityGroup],
      engine: props.engine,
      instanceType: props.instanceType,
      databaseName: props.databaseName,
      encryptionKey: this.kmsKey,
      masterUsername: props.masterUsername ?? 'dbadmin',
      multiAz: true,
      removalPolicy,
    })

    this.backupPlan = props.backupPlan ?? this.createBackupPlan(props.databaseName, removalPolicy)
    this.backupPlan.addSelection('BackupSelection', {
      resources: [backup.BackupResource.fromRdsDatabaseInstance(this.instance)],
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'MP.L2-3.8.9',
        satisfaction: 'partial',
        evidence:
          'Enrolled in an AWS Backup plan with 35-day retention, writing to a vault encrypted ' +
          'with a customer-managed KMS key',
        nagRuleIds: ['NIST.800.53.R5-RDSInBackupPlan'],
        caveat:
          'Evidences that backups exist, are retained, and are encrypted. Does not evidence ' +
          'restore testing.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.6',
        satisfaction: 'partial',
        evidence: 'Database security group created with allowAllOutbound=false',
        caveat:
          'Deny-by-default at this security group only. Ingress rules added by the caller are ' +
          'out of scope.',
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
      backupVaultName: `${name}-db-vault`,
      encryptionKey: this.kmsKey,
      removalPolicy,
    })

    return backup.BackupPlan.daily35DayRetention(this, 'BackupPlan', vault)
  }
}
