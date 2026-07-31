import { RemovalPolicy } from 'aws-cdk-lib'
import * as kms from 'aws-cdk-lib/aws-kms'
import { type Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { cmmc2Claim } from '../index.js'

export { type NonDestructiveRemovalPolicy } from '../../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'enableKeyRotation' | 'removalPolicy'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof kms.KeyProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface KeyProps extends Omit<kms.KeyProps, MandatedProps> {
  /**
   * Defaults to `RETAIN`. `DESTROY` is not representable.
   *
   * Deleting a KMS key makes every ciphertext under it permanently
   * unreadable - including backups and snapshots you still hold. That is not
   * a thing a stack teardown should be able to do by accident.
   */
  readonly removalPolicy?: NonDestructiveRemovalPolicy
}

/**
 * A KMS key configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `kms.Key`. Automatic annual rotation is mandated
 * and the key cannot be scheduled for deletion by a stack teardown.
 *
 * Most constructs in this library take their key from the `CompliantStack`
 * rather than being handed one, so reach for this when you want a key with its
 * own lifetime - shared with an outside party, or on a separate revocation
 * schedule from the rest of the stack.
 */
export class Key extends kms.Key {
  constructor(scope: Construct, id: string, props: KeyProps = {}) {
    super(scope, id, {
      ...props,
      enableKeyRotation: true,
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'supporting',
        evidence: 'Customer-managed key under this account, with automatic annual rotation enabled',
        nagRuleIds: ['NIST.800.53.R5-KMSBackingKeyRotationEnabled'],
        caveat:
          'A key protects nothing on its own. What it evidences is that the resources encrypted ' +
          'with it are under key material you control and rotate.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.11',
        satisfaction: 'supporting',
        evidence: 'Encryption performed by AWS KMS',
        caveat:
          'Whether the cryptography is FIPS-validated depends on the region and the endpoints in ' +
          'use, neither of which this construct controls.',
      }),
    ])
  }
}
