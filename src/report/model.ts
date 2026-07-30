import { type IConstruct } from 'constructs'

import {
  collectControlClaims,
  findUntaggableResources,
  type LocatedControlClaim,
  type SatisfactionLevel,
  type UntaggableResource,
} from '../index.js'
import { CMMC2_PRACTICES, type Cmmc2Practice, type Cmmc2PracticeId } from '../cmmc2/index.js'

/** A rule violation, shaped to match `ComplianceViolation` from the `/verify` subpath. */
export interface AttestationViolation {
  readonly ruleId: string
  readonly description: string
  readonly resources: readonly string[]
}

/** How completely a single practice is addressed by the constructs in scope. */
export interface PracticeCoverage {
  readonly practice: Cmmc2Practice
  /** Strongest satisfaction level claimed against this practice, if any. */
  readonly satisfaction?: SatisfactionLevel
  readonly claims: readonly LocatedControlClaim[]
}

/**
 * Everything the reports are rendered from.
 *
 * Deliberately JSON-serializable and deliberately free of timestamps: the
 * generated documents are committed, and a clock in the output would produce a
 * diff on every regeneration, which trains people to stop reading them.
 */
export interface Attestation {
  readonly framework: 'cmmc2'
  readonly revision: string
  /** Every practice in the framework, addressed or not. The denominator. */
  readonly coverage: readonly PracticeCoverage[]
  readonly untaggable: readonly UntaggableResource[]
  readonly violations: readonly AttestationViolation[]
}

export interface BuildAttestationOptions {
  /**
   * cdk-nag violations to reconcile against, normally
   * `verifyCompliance(scope).violations`.
   *
   * Passed in rather than computed here so this module stays free of cdk-nag,
   * which is an optional peer dependency.
   */
  readonly violations?: readonly AttestationViolation[]
}

/** Ordering used for satisfaction levels: the strongest claim wins. */
const STRENGTH: Record<SatisfactionLevel, number> = { supporting: 1, partial: 2, full: 3 }

/**
 * Collect claims from a construct tree and index them against the full
 * CMMC 2.0 Level 2 catalog.
 *
 * Every one of the 110 practices appears in the result, including those with no
 * claims. That is the point: a coverage report that lists only what you address
 * cannot tell an assessor what you do not.
 */
export function buildAttestation(
  scope: IConstruct,
  options: BuildAttestationOptions = {}
): Attestation {
  const claims = collectControlClaims(scope)

  const byPractice = new Map<string, LocatedControlClaim[]>()
  for (const located of claims) {
    if (located.claim.framework !== 'cmmc2') continue
    const existing = byPractice.get(located.claim.controlId)
    if (existing) existing.push(located)
    else byPractice.set(located.claim.controlId, [located])
  }

  const ids = Object.keys(CMMC2_PRACTICES) as Cmmc2PracticeId[]
  const coverage = ids.map(id => {
    const practiceClaims = byPractice.get(id) ?? []
    const strongest = practiceClaims.reduce<SatisfactionLevel | undefined>(
      (best, c) =>
        best === undefined || STRENGTH[c.claim.satisfaction] > STRENGTH[best]
          ? c.claim.satisfaction
          : best,
      undefined
    )

    return {
      practice: CMMC2_PRACTICES[id],
      claims: practiceClaims,
      ...(strongest === undefined ? {} : { satisfaction: strongest }),
    }
  })

  return {
    framework: 'cmmc2',
    revision: 'rev2',
    coverage,
    untaggable: findUntaggableResources(scope),
    violations: options.violations ?? [],
  }
}

/** Practices with at least one claim against them. */
export function addressedPractices(attestation: Attestation): PracticeCoverage[] {
  return attestation.coverage.filter(c => c.claims.length > 0)
}

/** Aggregate counts per capability domain, for the summary table. */
export interface DomainSummary {
  readonly domain: string
  readonly domainAbbrev: string
  readonly total: number
  readonly addressed: number
}

export function summarizeByDomain(attestation: Attestation): DomainSummary[] {
  const byDomain = new Map<string, { domain: string; total: number; addressed: number }>()

  for (const entry of attestation.coverage) {
    const key = entry.practice.domainAbbrev
    const bucket = byDomain.get(key) ?? { domain: entry.practice.domain, total: 0, addressed: 0 }
    bucket.total += 1
    if (entry.claims.length > 0) bucket.addressed += 1
    byDomain.set(key, bucket)
  }

  return [...byDomain.entries()].map(([domainAbbrev, v]) => ({
    domainAbbrev,
    domain: v.domain,
    total: v.total,
    addressed: v.addressed,
  }))
}
