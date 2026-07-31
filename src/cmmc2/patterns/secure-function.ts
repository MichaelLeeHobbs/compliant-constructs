import type * as kms from 'aws-cdk-lib/aws-kms'
import type * as logs from 'aws-cdk-lib/aws-logs'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { Function, type FunctionProps } from '../aws-lambda/index.js'
import { LogGroup } from '../aws-logs/index.js'
import { Queue } from '../aws-sqs/index.js'
import { cmmc2Claim } from '../index.js'

export interface SecureFunctionProps
  extends Omit<FunctionProps, 'logGroup' | 'deadLetterQueue' | 'deadLetterQueueEnabled'> {
  /** Retention for the log group created here. Defaults to one year. */
  readonly logRetention?: logs.RetentionDays

  /** Key for the log group, dead-letter queue and environment variables. Defaults to the stack's key. */
  readonly encryptionKey?: kms.IKey
}

/**
 * A Lambda function with the log group it needs.
 *
 * {@link Function} requires an explicit `logGroup`, because the one Lambda
 * creates for itself never appears in your template - untagged, unencrypted,
 * unbounded retention, and outside the scope boundary. This creates a compliant
 * one so that requirement costs nothing, plus a dead-letter queue so failed
 * async invocations leave a record rather than vanishing.
 *
 * Two findings remain, both contextual rather than fixable here:
 * `LambdaInsideVPC` and `LambdaConcurrency`. See {@link Function} for why
 * neither is mandated.
 *
 * Because this creates a subtree, adopting it changes construct paths. It is
 * for new stacks.
 */
export class SecureFunction extends Construct {
  readonly function: Function
  readonly logGroup: LogGroup
  readonly deadLetterQueue: Queue

  constructor(scope: Construct, id: string, props: SecureFunctionProps) {
    super(scope, id)

    this.logGroup = new LogGroup(this, 'LogGroup', {
      ...(props.logRetention === undefined ? {} : { retention: props.logRetention }),
      ...(props.encryptionKey === undefined ? {} : { encryptionKey: props.encryptionKey }),
    })

    // An async invocation that exhausts its retries is otherwise discarded with
    // no record that it happened, which is a poor answer to "show me every
    // failed operation".
    this.deadLetterQueue = new Queue(this, 'DeadLetterQueue', {
      ...(props.encryptionKey === undefined ? {} : { encryptionMasterKey: props.encryptionKey }),
    })

    this.function = new Function(this, 'Function', {
      ...props,
      logGroup: this.logGroup,
      deadLetterQueue: this.deadLetterQueue,
      ...(props.encryptionKey === undefined
        ? {}
        : { environmentEncryption: props.encryptionKey }),
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AU.L2-3.3.8',
        satisfaction: 'partial',
        evidence:
          'Function logs go to a declared log group encrypted with a customer-managed key, ' +
          'rather than the unencrypted one Lambda would create outside the stack',
        nagRuleIds: ['NIST.800.53.R5-CloudWatchLogGroupEncrypted'],
        caveat:
          'Protects the records at rest. Deletion is still governed by IAM, and retention by the ' +
          'log group rather than by any immutable store.',
      }),
    ])
  }
}

export { type FunctionProps } from '../aws-lambda/index.js'
