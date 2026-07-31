import type * as kms from 'aws-cdk-lib/aws-kms'
import * as sqs from 'aws-cdk-lib/aws-sqs'
import { type Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'encryption' | 'encryptionMasterKey' | 'enforceSSL'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof sqs.QueueProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface QueueProps extends Omit<sqs.QueueProps, MandatedProps> {
  /** Defaults to the stack's key. */
  readonly encryptionMasterKey?: kms.IKey
}

/**
 * An SQS queue configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `sqs.Queue`. Server-side encryption with a
 * customer-managed key and a TLS-only queue policy are both mandated.
 *
 * SQS deserves the same care as a database: a queue carrying CUI holds that CUI
 * at rest for as long as the retention period, and the default `SQS_MANAGED`
 * encryption leaves key custody with AWS.
 *
 * No dead-letter queue is created. A DLQ is a reliability control rather than a
 * compliance one, and a 1:1 wrapper should not provision resources the
 * construct it replaces would not.
 */
export class Queue extends sqs.Queue {
  constructor(scope: Construct, id: string, props: QueueProps = {}) {
    super(scope, id, {
      ...props,
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: resolveEncryptionKey(scope, props.encryptionMasterKey),
      enforceSSL: true,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Server-side encryption with a customer-managed KMS key',
        nagRuleIds: ['NIST.800.53.R5-SQSQueueSSE'],
        caveat:
          'Covers messages at rest in the queue. Says nothing about how producers or consumers ' +
          'handle the payload.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.8',
        satisfaction: 'partial',
        evidence: 'Queue policy denies any action where aws:SecureTransport is false',
        nagRuleIds: ['NIST.800.53.R5-SQSQueueSSL'],
        caveat:
          'Enforces TLS to the queue endpoint. Does not evidence protection of CUI in transit ' +
          'elsewhere in the system.',
      }),
    ])
  }
}
