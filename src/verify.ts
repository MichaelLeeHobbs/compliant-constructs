import { NIST80053R5Checks } from 'cdk-nag'
import { type IConstruct } from 'constructs'

/** A single rule violation, flattened from cdk-nag's plugin report. */
export interface ComplianceViolation {
  /** cdk-nag rule ID, e.g. `'NIST.800.53.R5-EFSInBackupPlan'`. */
  readonly ruleId: string
  /** Rule description, including the SP 800-53 control IDs it maps to. */
  readonly description: string
  /** Construct paths that violate the rule. */
  readonly resources: readonly string[]
}

/** Result of {@link verifyCompliance}. */
export interface ComplianceResult {
  readonly compliant: boolean
  readonly violations: readonly ComplianceViolation[]
}

/**
 * Run cdk-nag's NIST 800-53 Rev 5 pack over a construct tree and return the
 * violations.
 *
 * Uses cdk-nag's `validateScope` rather than registering a validation plugin,
 * deliberately. `Validations.of(app).addPlugins(...)` is the app-level way to
 * wire cdk-nag in, but it only exists in recent aws-cdk-lib - it is absent at
 * this library's declared peer floor of 2.165.0. `validateScope` works on every
 * version in range, which matters because this function backs the library's own
 * acceptance gate.
 *
 * Applications should still wire the pack in at the app level so it fails their
 * builds; see the README. This is for asserting a construct's compliance in
 * tests, and for the evidence report.
 */
export function verifyCompliance(scope: IConstruct): ComplianceResult {
  const pack = new NIST80053R5Checks(scope, { verbose: true })
  const report = pack.validateScope(scope)

  const violations = report.violations.map(v => ({
    ruleId: v.ruleName,
    description: v.description,
    resources: v.violatingResources
      .map(r => r.constructPath)
      .filter((p): p is string => p !== undefined),
  }))

  return { compliant: violations.length === 0, violations }
}

/**
 * Extract the SP 800-53 control IDs a cdk-nag rule maps to.
 *
 * cdk-nag embeds them in each rule's description as `(Control IDs: AU-9(3),
 * CP-9d, ...)`, or `(Control ID: ...)` for a single one. Parsing them is what
 * lets a claim reconcile against cdk-nag's own view of the same resource.
 */
export function parseNagControlIds(description: string): string[] {
  const match = /\(Control IDs?: ([^)]*(?:\([^)]*\)[^)]*)*)\)/.exec(description)
  if (!match?.[1]) return []

  return match[1]
    .split(',')
    .map(s => s.trim())
    .filter(s => s !== '')
}
