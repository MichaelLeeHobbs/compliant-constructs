import { type ControlClaim, type SatisfactionLevel } from '../index.js'

/** Framework identifier stamped onto every claim produced by this module. */
export const CMMC2_FRAMEWORK_ID = 'cmmc2'

/**
 * CMMC 2.0 Level 2 practice identifiers.
 *
 * Level 2 practices correspond 1:1 to NIST SP 800-171 Rev 2 security
 * requirements, which is why each entry carries its `nist800171` mapping.
 *
 * This catalog is deliberately incomplete. It grows as constructs land, and
 * only ever contains practices some construct in this library actually claims
 * against - an entry here with no claims pointing at it would be a promise the
 * code does not keep.
 */
export type Cmmc2PracticeId =
  | 'AC.L2-3.1.3'
  | 'AU.L2-3.3.1'
  | 'MP.L2-3.8.9'
  | 'SC.L2-3.13.6'
  | 'SC.L2-3.13.8'
  | 'SC.L2-3.13.11'
  | 'SC.L2-3.13.16'

/** A single CMMC 2.0 practice and its NIST SP 800-171 Rev 2 origin. */
export interface Cmmc2Practice {
  readonly id: Cmmc2PracticeId
  /** Capability domain, e.g. `'System and Communications Protection'`. */
  readonly domain: string
  /** CMMC level at which the practice is assessed. */
  readonly level: 2
  /** Requirement text, abridged. */
  readonly title: string
  /** Corresponding NIST SP 800-171 Rev 2 requirement number. */
  readonly nist800171: string
}

export const CMMC2_PRACTICES: Readonly<Record<Cmmc2PracticeId, Cmmc2Practice>> = {
  'AC.L2-3.1.3': {
    id: 'AC.L2-3.1.3',
    domain: 'Access Control',
    level: 2,
    title: 'Control the flow of CUI in accordance with approved authorizations.',
    nist800171: '3.1.3',
  },
  'AU.L2-3.3.1': {
    id: 'AU.L2-3.3.1',
    domain: 'Audit and Accountability',
    level: 2,
    title:
      'Create and retain system audit logs and records to the extent needed to enable the ' +
      'monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.',
    nist800171: '3.3.1',
  },
  'MP.L2-3.8.9': {
    id: 'MP.L2-3.8.9',
    domain: 'Media Protection',
    level: 2,
    title: 'Protect the confidentiality of backup CUI at storage locations.',
    nist800171: '3.8.9',
  },
  'SC.L2-3.13.6': {
    id: 'SC.L2-3.13.6',
    domain: 'System and Communications Protection',
    level: 2,
    title:
      'Deny network communications traffic by default and allow network communications traffic ' +
      'by exception.',
    nist800171: '3.13.6',
  },
  'SC.L2-3.13.8': {
    id: 'SC.L2-3.13.8',
    domain: 'System and Communications Protection',
    level: 2,
    title:
      'Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during ' +
      'transmission unless otherwise protected by alternative physical safeguards.',
    nist800171: '3.13.8',
  },
  'SC.L2-3.13.11': {
    id: 'SC.L2-3.13.11',
    domain: 'System and Communications Protection',
    level: 2,
    title: 'Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.',
    nist800171: '3.13.11',
  },
  'SC.L2-3.13.16': {
    id: 'SC.L2-3.13.16',
    domain: 'System and Communications Protection',
    level: 2,
    title: 'Protect the confidentiality of CUI at rest.',
    nist800171: '3.13.16',
  },
}

/** Input to {@link cmmc2Claim}. */
export interface Cmmc2ClaimProps {
  /** Practice being claimed against. Typed, so a typo fails at compile time. */
  readonly practice: Cmmc2PracticeId
  readonly satisfaction: SatisfactionLevel
  /** Concrete, resource-property-level statement of the evidence. */
  readonly evidence: string
  /** cdk-nag rule IDs covering the same ground. */
  readonly nagRuleIds?: readonly string[]
  /** What this claim does not cover. Required in practice for `partial` claims. */
  readonly caveat?: string
}

/**
 * Build a CMMC 2.0 control claim.
 *
 * Preferred over constructing a {@link ControlClaim} by hand because the
 * practice ID is checked against {@link Cmmc2PracticeId} at compile time.
 */
export function cmmc2Claim(props: Cmmc2ClaimProps): ControlClaim {
  return {
    framework: CMMC2_FRAMEWORK_ID,
    controlId: props.practice,
    satisfaction: props.satisfaction,
    evidence: props.evidence,
    ...(props.nagRuleIds === undefined ? {} : { nagRuleIds: props.nagRuleIds }),
    ...(props.caveat === undefined ? {} : { caveat: props.caveat }),
  }
}
