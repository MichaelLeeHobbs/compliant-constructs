import type * as kms from 'aws-cdk-lib/aws-kms'
import * as sns from 'aws-cdk-lib/aws-sns'
import { type Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'masterKey' | 'enforceSSL'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof sns.TopicProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface TopicProps extends Omit<sns.TopicProps, MandatedProps> {
  /** Defaults to the stack's key. */
  readonly masterKey?: kms.IKey
}

/**
 * An SNS topic configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `sns.Topic`, encrypted with a customer-managed key
 * and with a topic policy denying non-TLS publishing.
 *
 * Topics are easy to overlook because they look transient, but a notification
 * carrying CUI is CUI - and an unencrypted topic is readable by anyone holding
 * `sns:Subscribe` without any key check at all.
 */
export class Topic extends sns.Topic {
  constructor(scope: Construct, id: string, props: TopicProps = {}) {
    super(scope, id, {
      ...props,
      masterKey: resolveEncryptionKey(scope, props.masterKey),
      enforceSSL: true,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Server-side encryption with a customer-managed KMS key',
        nagRuleIds: ['NIST.800.53.R5-SNSEncryptedKMS'],
        caveat:
          'Covers messages held by SNS. Once delivered to a subscriber, protection is that ' +
          'subscriber’s concern.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.8',
        satisfaction: 'partial',
        evidence: 'Topic policy denies publishing where aws:SecureTransport is false',
        nagRuleIds: ['NIST.800.53.R5-SNSTopicSSLPublishOnly'],
        caveat:
          'Enforces TLS for publishers. Delivery to subscribers uses whatever protocol the ' +
          'subscription specifies, which this construct does not control.',
      }),
    ])
  }
}
