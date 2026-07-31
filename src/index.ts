import { type IConstruct } from 'constructs'

/**
 * Construct-tree metadata key under which control claims are recorded.
 *
 * Claims are attached with `node.addMetadata`, which means they survive into
 * the synthesized cloud assembly manifest as well as being readable in-process.
 */
export const CONTROL_CLAIM_METADATA_KEY = 'compliant-constructs:control-claim'

/**
 * How completely a construct's configuration satisfies a control.
 *
 * Almost nothing an IaC library does is `full` on its own - a compliance
 * control usually also requires policy, procedure, or evidence that lives
 * outside the deployed infrastructure. Being honest about this is the point:
 * the generated coverage table is only useful to an assessor if it does not
 * overclaim.
 */
export type SatisfactionLevel =
  /** The control is met by this resource's configuration alone. */
  | 'full'
  /** The configuration meets the technical portion; other evidence is still required. */
  | 'partial'
  /** Does not satisfy the control, but produces evidence that supports assessing it. */
  | 'supporting'

/**
 * A single assertion that some property of a construct speaks to some control.
 *
 * Claims are authored inline at the construct that implements them, so a claim
 * cannot drift away from the code backing it.
 */
export interface ControlClaim {
  /** Framework this control belongs to, e.g. `'cmmc2'`. */
  readonly framework: string

  /**
   * Revision of the framework the claim is made against, e.g. `'rev2'`.
   *
   * Recorded because control text and numbering move between revisions, and a
   * generated evidence report has to say which one it is describing.
   */
  readonly frameworkRevision?: string

  /** Control or practice identifier within the framework, e.g. `'SC.L2-3.13.16'`. */
  readonly controlId: string

  /** How completely this construct's configuration satisfies the control. */
  readonly satisfaction: SatisfactionLevel

  /**
   * What, concretely, constitutes the evidence - stated so an assessor reading
   * the generated report can tie it to a deployed resource property.
   *
   * Good: `'Encrypted=true with a customer-managed KMS key'`.
   * Bad: `'the file system is secure'`.
   */
  readonly evidence: string

  /**
   * cdk-nag rule IDs covering the same ground, used to join this claim against
   * cdk-nag's own CSV report so the two views reconcile.
   */
  readonly nagRuleIds?: readonly string[]

  /**
   * What this claim explicitly does NOT cover. Surfaced verbatim in the
   * coverage table, so a `partial` claim always says what is still owed.
   */
  readonly caveat?: string
}

/** A claim paired with the construct path it was recorded against. */
export interface LocatedControlClaim {
  /** Full construct path, e.g. `'MyStack/Storage/FileSystem'`. */
  readonly path: string
  readonly claim: ControlClaim
}

/**
 * Record control claims against a construct.
 *
 * Intended to be called by construct implementations in their own constructor,
 * not by application code.
 */
export function addControlClaims(scope: IConstruct, claims: readonly ControlClaim[]): void {
  for (const claim of claims) {
    // `false` for stackTrace: claims are declarative metadata, and capturing a
    // stack trace per claim measurably slows synth on large trees.
    scope.node.addMetadata(CONTROL_CLAIM_METADATA_KEY, claim, { stackTrace: false })
  }
}

/**
 * Collect every control claim recorded anywhere at or below `root`.
 *
 * Ordering is stable (construct-tree order, then declaration order within a
 * construct) so generated reports produce clean diffs between runs.
 */
export function collectControlClaims(root: IConstruct): LocatedControlClaim[] {
  const found: LocatedControlClaim[] = []

  for (const construct of root.node.findAll()) {
    for (const entry of construct.node.metadata) {
      if (entry.type !== CONTROL_CLAIM_METADATA_KEY) continue
      found.push({ path: construct.node.path, claim: entry.data as ControlClaim })
    }
  }

  return found
}

export {
  REQUIRED_TAG_KEYS,
  applyRequiredTags,
  findUntaggableResources,
  type RequiredTags,
  type UntaggableResource,
} from './tagging.js'

export {
  type NonDestructiveRemovalPolicy,
  type SnapshottableRemovalPolicy,
} from './removal-policy.js'
