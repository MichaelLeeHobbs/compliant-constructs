import { type ControlClaim, type SatisfactionLevel } from '../index.js'
import { CMMC2_PRACTICES, type Cmmc2PracticeId, type Cmmc2Revision } from './catalog.generated.js'

export {
  CMMC2_PRACTICES,
  CMMC2_PRACTICE_COUNT,
  type Cmmc2Practice,
  type Cmmc2PracticeId,
  type Cmmc2RequirementKind,
  type Cmmc2Revision,
} from './catalog.generated.js'

/** Framework identifier stamped onto every claim produced by this module. */
export const CMMC2_FRAMEWORK_ID = 'cmmc2'

/**
 * SP 800-171 revision this module's catalog is built against.
 *
 * CMMC Level 2 is pinned to Rev 2 by 32 CFR Part 170 and the May 2024 DFARS
 * class deviation, notwithstanding that NIST withdrew Rev 2 in favour of Rev 3.
 * Rev 3 rulemaking is in progress; when it lands, this becomes a union.
 */
export const CMMC2_REVISION: Cmmc2Revision = 'rev2'

/** Input to {@link cmmc2Claim}. */
export interface Cmmc2ClaimProps {
  /** Practice being claimed against. Typed, so a typo fails at compile time. */
  readonly practice: Cmmc2PracticeId
  readonly satisfaction: SatisfactionLevel
  /** Concrete, resource-property-level statement of the evidence. */
  readonly evidence: string
  /** cdk-nag rule IDs covering the same ground. */
  readonly nagRuleIds?: readonly string[]
  /** What this claim does not cover. Expected on every `partial` claim. */
  readonly caveat?: string
}

/**
 * Build a CMMC 2.0 control claim.
 *
 * Preferred over constructing a {@link ControlClaim} by hand: the practice ID
 * is checked against the generated catalog at compile time, and again at
 * runtime for the benefit of JavaScript consumers who have no such guarantee.
 */
export function cmmc2Claim(props: Cmmc2ClaimProps): ControlClaim {
  if (!(props.practice in CMMC2_PRACTICES)) {
    throw new Error(`${props.practice} is not a CMMC 2.0 Level 2 practice`)
  }

  return {
    framework: CMMC2_FRAMEWORK_ID,
    frameworkRevision: CMMC2_REVISION,
    controlId: props.practice,
    satisfaction: props.satisfaction,
    evidence: props.evidence,
    ...(props.nagRuleIds === undefined ? {} : { nagRuleIds: props.nagRuleIds }),
    ...(props.caveat === undefined ? {} : { caveat: props.caveat }),
  }
}
