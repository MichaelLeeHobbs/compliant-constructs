import * as acm from 'aws-cdk-lib/aws-certificatemanager'
import type * as route53 from 'aws-cdk-lib/aws-route53'
import { type Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'validation' | 'keyAlgorithm'

/** Fails to compile if any mandated prop stops existing upstream. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof acm.CertificateProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface CertificateProps extends Omit<acm.CertificateProps, MandatedProps> {
  /**
   * Hosted zone used to prove control of the domain. Required.
   *
   * DNS validation is mandated because it is the only method ACM can renew
   * without a human. Email validation depends on somebody reading a mailbox
   * and clicking a link, and an expired certificate on a CUI endpoint is an
   * outage that people work around by disabling verification.
   */
  readonly hostedZone: route53.IHostedZone
}

/**
 * An ACM certificate that will still be valid next year.
 *
 * A drop-in replacement for `acm.Certificate` with DNS validation and an
 * RSA 2048 key mandated.
 *
 * SC.L2-3.13.15 asks you to protect the authenticity of communications
 * sessions. A certificate is how a client knows it is talking to your service
 * rather than something in the middle, and an expired one turns that guarantee
 * into a dialog people click through.
 */
export class Certificate extends acm.Certificate {
  constructor(scope: Construct, id: string, props: CertificateProps) {
    const { hostedZone, ...rest } = props

    super(scope, id, {
      ...rest,
      validation: acm.CertificateValidation.fromDns(hostedZone),
      keyAlgorithm: acm.KeyAlgorithm.RSA_2048,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.15',
        satisfaction: 'partial',
        evidence:
          'ACM certificate with DNS validation, renewed automatically for as long as the ' +
          'validation record remains in the zone',
        caveat:
          'Establishes the identity of the endpoint. Whether clients verify it, and what they do ' +
          'when verification fails, is client behaviour.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.8',
        satisfaction: 'supporting',
        evidence: 'Provides the certificate a TLS listener needs in order to exist at all',
        caveat:
          'A certificate does not encrypt anything by itself. The listener using it decides the ' +
          'protocol version and cipher suite.',
      }),
    ])
  }
}
