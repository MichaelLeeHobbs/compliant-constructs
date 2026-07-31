import { RemovalPolicy, type Duration } from 'aws-cdk-lib'
import type * as kms from 'aws-cdk-lib/aws-kms'
import * as sm from 'aws-cdk-lib/aws-secretsmanager'
import { type Construct } from 'constructs'

import { addControlClaims, type NonDestructiveRemovalPolicy } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export { type NonDestructiveRemovalPolicy } from '../../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'encryptionKey' | 'removalPolicy'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof sm.SecretProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface SecretProps extends Omit<sm.SecretProps, MandatedProps> {
  /** Defaults to the stack's key. */
  readonly encryptionKey?: kms.IKey

  /**
   * Rotation to attach, if this secret has a rotation strategy that can be
   * expressed declaratively.
   *
   * Left unset, the secret is created without rotation and cdk-nag's
   * `SecretsManagerRotationEnabled` will flag it - correctly. See the note on
   * the class.
   */
  readonly hostedRotation?: sm.HostedRotation

  /** How often the hosted rotation runs, when one is supplied. Defaults to 30 days. */
  readonly rotateAfter?: Duration

  /** Defaults to `RETAIN`. */
  readonly removalPolicy?: NonDestructiveRemovalPolicy
}

/**
 * A Secrets Manager secret configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `secretsmanager.Secret`, encrypted with a
 * customer-managed key rather than the AWS-managed default.
 *
 * **Rotation cannot be mandated here, and that is a real gap rather than an
 * oversight.** Rotating a secret means knowing what consumes it: a database
 * credential needs a rotation Lambda that can reach the database, an API key
 * needs whatever the third party's rotation flow is. A generic secret construct
 * has no way to know. Pass `hostedRotation` where AWS ships a strategy for your
 * secret type, or call `addRotationSchedule()` yourself. Until you do,
 * `SecretsManagerRotationEnabled` will flag the secret, which is the correct
 * signal rather than something to suppress.
 *
 * `DatabaseInstance` in `cmmc2/aws-rds` does wire rotation, because there the
 * consumer is known.
 */
export class Secret extends sm.Secret {
  constructor(scope: Construct, id: string, props: SecretProps = {}) {
    super(scope, id, {
      ...props,
      encryptionKey: resolveEncryptionKey(scope, props.encryptionKey),
      removalPolicy: props.removalPolicy ?? RemovalPolicy.RETAIN,
    })

    if (props.hostedRotation !== undefined) {
      this.addRotationSchedule('RotationSchedule', {
        hostedRotation: props.hostedRotation,
        ...(props.rotateAfter === undefined ? {} : { automaticallyAfter: props.rotateAfter }),
      })
    }

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Encrypted at rest with a customer-managed KMS key',
        nagRuleIds: ['NIST.800.53.R5-SecretsManagerUsingKMSKey'],
        caveat:
          'Protects the stored value. Says nothing about how the secret is handled once a ' +
          'consumer has retrieved it.',
      }),
      cmmc2Claim({
        practice: 'IA.L2-3.5.10',
        satisfaction: props.hostedRotation === undefined ? 'supporting' : 'partial',
        evidence:
          props.hostedRotation === undefined
            ? 'Credential stored encrypted rather than in configuration or source'
            : 'Credential stored encrypted, on an automatic rotation schedule',
        ...(props.hostedRotation === undefined
          ? {}
          : { nagRuleIds: ['NIST.800.53.R5-SecretsManagerRotationEnabled'] }),
        caveat:
          props.hostedRotation === undefined
            ? 'No rotation is configured. Storing a credential encrypted is weaker evidence than ' +
              'rotating it - attach a rotation schedule where the consumer allows one.'
            : 'Rotation is scheduled. Whether consumers pick up the new value without downtime ' +
              'depends on how they read the secret.',
      }),
    ])
  }
}
