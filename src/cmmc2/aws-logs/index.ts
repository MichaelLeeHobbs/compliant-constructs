import { ArnFormat, RemovalPolicy, Stack } from 'aws-cdk-lib'
import * as iam from 'aws-cdk-lib/aws-iam'
import type * as kms from 'aws-cdk-lib/aws-kms'
import * as logs from 'aws-cdk-lib/aws-logs'
import { type Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export { type NonDestructiveRemovalPolicy } from '../../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'encryptionKey' | 'retention' | 'removalPolicy'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof logs.LogGroupProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface LogGroupProps extends Omit<logs.LogGroupProps, MandatedProps> {
  /** Defaults to the stack's key. */
  readonly encryptionKey?: kms.IKey

  /**
   * How long records are kept. Defaults to one year.
   *
   * `INFINITE` is allowed. What is not allowed is leaving it unset: the CDK
   * would then apply its own default, and "however long the framework happened
   * to choose" is not a retention decision anybody made.
   */
  readonly retention?: logs.RetentionDays

  /** Defaults to `RETAIN`, so a stack teardown cannot destroy audit records. */
  readonly removalPolicy?: NonDestructiveRemovalPolicy
}

/**
 * A CloudWatch log group configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `logs.LogGroup`, encrypted with a customer-managed
 * key and with an explicit retention period.
 *
 * Encrypting a log group needs more than pointing at a key. CloudWatch Logs
 * acts on its own behalf rather than as the caller, so the key policy has to
 * name the service explicitly - IAM delegation is not enough, and the deploy
 * fails at CreateLogGroup if it is missing. This construct adds that statement
 * to the key when it attaches, scoped by an encryption-context condition so the
 * grant reaches log groups in this account and region only.
 *
 * That is the general pattern for the stack-scoped key: its policy grows from
 * what actually uses it, rather than being written permissively up front and
 * never pruned.
 */
export class LogGroup extends logs.LogGroup {
  constructor(scope: Construct, id: string, props: LogGroupProps = {}) {
    const encryptionKey = resolveEncryptionKey(scope, props.encryptionKey)
    grantCloudWatchLogs(scope, encryptionKey)

    super(scope, id, {
      ...props,
      encryptionKey,
      retention: props.retention ?? logs.RetentionDays.ONE_YEAR,
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence: `Log group retained for ${describeRetention(props.retention)}`,
        caveat:
          'Retains whatever is written to it. Whether the records are sufficient to investigate ' +
          'unauthorised activity depends on what the emitting service logs.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.8',
        satisfaction: 'partial',
        evidence:
          'Encrypted at rest with a customer-managed key; the key policy grants CloudWatch Logs ' +
          'only within this account and region',
        nagRuleIds: ['NIST.800.53.R5-CloudWatchLogGroupEncrypted'],
        caveat:
          'Protects records at rest from readers without key access. Does not prevent deletion ' +
          'by a principal holding logs:DeleteLogGroup - that is an IAM concern.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'supporting',
        evidence: 'KmsKeyId set to a customer-managed key',
        nagRuleIds: ['NIST.800.53.R5-CloudWatchLogGroupEncrypted'],
        caveat: 'Applies to log data only, and only to records written after the key was attached.',
      }),
    ])
  }
}

function describeRetention(retention?: logs.RetentionDays): string {
  if (retention === undefined) return '1 year (default)'
  return retention === logs.RetentionDays.INFINITE ? 'an unlimited period' : `${retention} days`
}

/**
 * Regions already granted, recorded on the key itself.
 *
 * A key policy cannot carry two statements with the same sid, so the grant has
 * to happen once per key per region no matter how many log groups attach.
 *
 * The bookkeeping lives on the key rather than in a module-level map because
 * this package ships one bundle per subpath with code splitting off: a
 * `LogGroup` created from `cmmc2/aws-logs` and one created inside
 * `cmmc2/patterns` run different copies of this module, and therefore
 * different module-level state. `Symbol.for` resolves to the same symbol in
 * every copy, so the dedupe holds across them - the same reason
 * `CompliantStack.of` uses a marker instead of `instanceof`.
 */
const GRANTED_REGIONS = Symbol.for('@ubercode/compliant-constructs.logsKeyGrantRegions')

function grantCloudWatchLogs(scope: Construct, key: kms.IKey): void {
  const stack = Stack.of(scope)
  const carrier = key as unknown as Record<symbol, Set<string> | undefined>
  const regions = (carrier[GRANTED_REGIONS] ??= new Set<string>())

  if (regions.has(stack.region)) return
  regions.add(stack.region)

  key.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: 'AllowCloudWatchLogsEncryption',
      principals: [new iam.ServicePrincipal(`logs.${stack.region}.amazonaws.com`)],
      actions: [
        'kms:Encrypt*',
        'kms:Decrypt*',
        'kms:ReEncrypt*',
        'kms:GenerateDataKey*',
        'kms:Describe*',
      ],
      resources: ['*'],
      // Without this the grant would let CloudWatch Logs use the key on behalf
      // of any log group in any account it serves. The condition pins it to
      // log groups in this account and region.
      conditions: {
        ArnLike: {
          // Log group ARNs use `log-group:name`, not `log-group/name`.
          'kms:EncryptionContext:aws:logs:arn': stack.formatArn({
            service: 'logs',
            resource: 'log-group',
            resourceName: '*',
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
          }),
        },
      },
    }),
    // Imported keys have no policy we can edit; warn rather than fail, since
    // the caller may have granted it out of band.
    true
  )
}
