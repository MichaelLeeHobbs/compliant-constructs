import { RemovalPolicy } from 'aws-cdk-lib'
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb'
import type * as kms from 'aws-cdk-lib/aws-kms'
import { type Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export { type NonDestructiveRemovalPolicy } from '../../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'encryption' | 'pointInTimeRecoverySpecification' | 'removalPolicy'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof dynamodb.TablePropsV2 ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface TableProps extends Omit<dynamodb.TablePropsV2, MandatedProps> {
  /** Defaults to the stack's key. */
  readonly encryptionKey?: kms.IKey

  /**
   * How far back point-in-time recovery can restore. Defaults to 35 days, the
   * maximum DynamoDB allows.
   */
  readonly recoveryPeriodInDays?: number

  /** Defaults to `RETAIN`. */
  readonly removalPolicy?: NonDestructiveRemovalPolicy
}

/**
 * A DynamoDB table configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `dynamodb.TableV2`. Encryption with a
 * customer-managed key and point-in-time recovery are both mandated.
 *
 * PITR is mandated even though the NIST 800-53 R5 pack does not currently check
 * for it. A table is frequently the only copy of the data it holds, and PITR is
 * the only thing standing between a bad write and permanent loss - which is
 * squarely what MP.L2-3.8.9 is about. Being stricter than the rule pack is
 * fine; the pack is a floor.
 */
export class Table extends dynamodb.TableV2 {
  constructor(scope: Construct, id: string, props: TableProps) {
    const recoveryPeriodInDays = props.recoveryPeriodInDays ?? 35

    super(scope, id, {
      ...props,
      encryption: dynamodb.TableEncryptionV2.customerManagedKey(
        resolveEncryptionKey(scope, props.encryptionKey)
      ),
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
        recoveryPeriodInDays,
      },
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Encrypted at rest with a customer-managed KMS key',
        caveat:
          'Covers the table, its indexes and its streams. Exports to S3 are encrypted by the ' +
          'destination bucket, not by this setting.',
      }),
      cmmc2Claim({
        practice: 'MP.L2-3.8.9',
        satisfaction: 'partial',
        evidence: `Point-in-time recovery enabled with a ${recoveryPeriodInDays}-day window`,
        caveat:
          'Allows restore to any second in the window. Does not evidence that a restore has ever ' +
          'been tested, nor retention beyond the window.',
      }),
    ])
  }
}
