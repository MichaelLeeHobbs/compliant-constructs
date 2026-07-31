import { Duration, RemovalPolicy } from 'aws-cdk-lib'
import type * as kms from 'aws-cdk-lib/aws-kms'
import * as rds from 'aws-cdk-lib/aws-rds'
import { type Construct } from 'constructs'

import { addControlClaims, type SnapshottableRemovalPolicy } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export { type SnapshottableRemovalPolicy } from '../../index.js'

/**
 * Props this wrapper takes ownership of, and therefore removes from the
 * caller's reach entirely.
 */
type MandatedProps =
  | 'storageEncrypted'
  | 'storageEncryptionKey'
  | 'publiclyAccessible'
  | 'deletionProtection'
  | 'iamAuthentication'
  | 'autoMinorVersionUpgrade'
  | 'enablePerformanceInsights'
  | 'performanceInsightEncryptionKey'
  | 'copyTagsToSnapshot'
  | 'credentials'
  | 'monitoringInterval'
  | 'removalPolicy'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof rds.DatabaseInstanceProps
  ? true
  : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

/** Minimum backup retention this wrapper will accept. */
export const MINIMUM_BACKUP_RETENTION_DAYS = 7

export interface DatabaseInstanceProps extends Omit<rds.DatabaseInstanceProps, MandatedProps> {
  /**
   * Customer-managed key used for storage encryption, the generated
   * credentials secret, and Performance Insights. Required.
   */
  readonly encryptionKey?: kms.IKey

  /** Master username. Credentials are always a generated, CMK-encrypted secret. */
  readonly masterUsername: string

  /**
   * Backup retention. Defaults to 35 days; must be at least
   * {@link MINIMUM_BACKUP_RETENTION_DAYS}.
   */
  readonly backupRetention?: Duration

  /**
   * How often the master credential is rotated. Defaults to 30 days.
   *
   * Rotation is not optional. See the note on the class about the two cdk-nag
   * findings it produces.
   */
  readonly rotateMasterCredentialAfter?: Duration

  /**
   * Enhanced monitoring granularity. Defaults to 60 seconds; zero is rejected.
   *
   * Enhanced monitoring reports OS-level metrics that the standard CloudWatch
   * metrics do not. It is what cdk-nag's `RDSEnhancedMonitoringEnabled` asks
   * for, and what a database holding CUI should be emitting.
   */
  readonly monitoringInterval?: Duration

  /** Defaults to `RETAIN`. `SNAPSHOT` is permitted here; `DESTROY` is not. */
  readonly removalPolicy?: SnapshottableRemovalPolicy
}

/**
 * An RDS instance configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `rds.DatabaseInstance`. Storage encryption with a
 * customer-managed key, a CMK-encrypted generated credential secret on an
 * automatic rotation schedule, IAM authentication, deletion protection,
 * Performance Insights encrypted with the same key, and no public accessibility
 * are all mandated.
 *
 * `cloudwatchLogsExports` defaults to the full set for the engine where this
 * library knows it; supplying your own replaces that.
 *
 * **Two cdk-nag findings are outstanding by design.** Enabling credential
 * rotation makes the CDK attach an ingress rule from the rotation Lambda's
 * security group to the database, whose port is a CloudFormation token
 * (`Fn::GetAtt` on the endpoint). cdk-nag's `EC2RestrictedCommonPorts` and
 * `EC2RestrictedSSH` rules cannot prove that token is not 22 or 3389, so they
 * flag conservatively. Both are false positives. The alternative - defaulting
 * rotation off so the report looks clean - would trade a real control for a
 * cosmetic one, so it is not on offer.
 */
export class DatabaseInstance extends rds.DatabaseInstance {
  constructor(scope: Construct, id: string, props: DatabaseInstanceProps) {
    const backupRetention = props.backupRetention ?? Duration.days(35)
    const monitoringInterval = props.monitoringInterval ?? Duration.seconds(60)

    if (monitoringInterval.toSeconds() === 0) {
      throw new Error('monitoringInterval must be non-zero: enhanced monitoring cannot be disabled')
    }

    if (backupRetention.toDays() < MINIMUM_BACKUP_RETENTION_DAYS) {
      throw new Error(
        `backupRetention must be at least ${MINIMUM_BACKUP_RETENTION_DAYS} days, ` +
          `got ${backupRetention.toDays()}`
      )
    }

    const logExports = defaultLogExports(props.engine)
    const encryptionKey = resolveEncryptionKey(scope, props.encryptionKey)

    super(scope, id, {
      // Spread conditionally: under exactOptionalPropertyTypes an explicit
      // `undefined` is not the same as an absent key, and passing one here
      // would override the caller's own value with nothing.
      ...(logExports === undefined ? {} : { cloudwatchLogsExports: logExports }),
      ...props,
      backupRetention,
      credentials: rds.Credentials.fromGeneratedSecret(props.masterUsername, {
        encryptionKey,
      }),
      storageEncrypted: true,
      storageEncryptionKey: encryptionKey,
      publiclyAccessible: false,
      deletionProtection: true,
      iamAuthentication: true,
      autoMinorVersionUpgrade: true,
      enablePerformanceInsights: true,
      performanceInsightEncryptionKey: encryptionKey,
      copyTagsToSnapshot: true,
      monitoringInterval,
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    })

    this.addRotationSingleUser({
      automaticallyAfter: props.rotateMasterCredentialAfter ?? Duration.days(30),
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence:
          'StorageEncrypted=true with a customer-managed KMS key; automated backups and ' +
          'snapshots inherit it',
        nagRuleIds: ['NIST.800.53.R5-RDSStorageEncrypted'],
        caveat:
          'Covers storage at rest. Does not evidence encryption of data exported from the ' +
          'database, nor key custody procedures.',
      }),
      cmmc2Claim({
        practice: 'IA.L2-3.5.3',
        satisfaction: 'supporting',
        evidence:
          'IAM database authentication enabled, allowing credentials to be issued per-principal ' +
          'rather than shared',
        caveat:
          'Enables the mechanism. Whether multifactor authentication is actually enforced for ' +
          'database access depends on the IAM principals and identity provider in use.',
      }),
      cmmc2Claim({
        practice: 'AC.L2-3.1.3',
        satisfaction: 'partial',
        evidence: 'PubliclyAccessible=false; reachable only from within the VPC',
        nagRuleIds: ['NIST.800.53.R5-RDSInstancePublicAccess'],
        caveat:
          'Prevents exposure to the internet. Access from within the VPC is governed by the ' +
          'security groups the caller supplies.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence:
          'Engine logs exported to CloudWatch Logs; Performance Insights and enhanced OS-level ' +
          'monitoring enabled, both encrypted with the CMK',
        nagRuleIds: [
          'NIST.800.53.R5-RDSLoggingEnabled',
          'NIST.800.53.R5-RDSEnhancedMonitoringEnabled',
        ],
        caveat:
          'Produces the records. Retention, protection and review of them are properties of the ' +
          'log group and of process.',
      }),
      cmmc2Claim({
        practice: 'MP.L2-3.8.9',
        satisfaction: 'partial',
        evidence: `Automated backups retained for ${backupRetention.toDays()} days, encrypted with the CMK`,
        caveat:
          'Automated backups only. The instance is not enrolled in an AWS Backup plan, so ' +
          'retention beyond the RDS window is not governed here - see EncryptedDatabaseInstance.',
      }),
      cmmc2Claim({
        practice: 'CM.L2-3.4.1',
        satisfaction: 'supporting',
        evidence:
          'AutoMinorVersionUpgrade=true and DeletionProtection=true, so the instance stays ' +
          'patched and cannot be removed by an unreviewed stack change',
        caveat:
          'Baseline configuration of this one resource. Says nothing about the inventory or ' +
          'change control process the practice actually asks for.',
      }),
    ])
  }
}

/**
 * Log exports that carry security-relevant events for engines we recognise.
 *
 * cdk-nag's `RDSLoggingEnabled` checks for the full documented set per engine,
 * which is why `upgrade` appears alongside the query log. Unrecognised engines
 * get nothing rather than a guess - a wrong export name fails at deploy.
 */
function defaultLogExports(engine: rds.IInstanceEngine): string[] | undefined {
  switch (engine.engineType) {
    case 'postgres':
      return ['postgresql', 'upgrade']
    case 'mysql':
    case 'mariadb':
      return ['audit', 'error', 'general', 'slowquery']
    default:
      return undefined
  }
}
