import { Stack, type StackProps } from 'aws-cdk-lib'
import { type Construct } from 'constructs'

import { applyRequiredTags, type RequiredTags } from '../tagging.js'

export interface CompliantStackProps extends Omit<StackProps, 'tags'> {
  /**
   * Tags applied to every resource in the stack.
   *
   * Required and typed, replacing `StackProps.tags`. A free-form tag map makes
   * it possible to deploy a stack holding CUI with no indication that it does,
   * which is precisely the thing an assessment scope boundary has to answer.
   */
  readonly requiredTags: RequiredTags
}

/**
 * A stack whose resources are tagged for assessment scoping by construction.
 *
 * Deliberately does not register cdk-nag itself. Wiring a validation plugin
 * from a stack constructor would be surprising, would fire once per stack, and
 * `Validations.of()` does not exist at this library's peer floor. Applications
 * should wire the pack in at the app level instead:
 *
 * ```ts
 * Validations.of(app).addPlugins(new NIST80053R5Checks(app))
 * ```
 *
 * For asserting compliance in tests, use `verifyCompliance()`.
 */
export class CompliantStack extends Stack {
  /** The tags applied to this stack, readable by constructs within it. */
  readonly requiredTags: RequiredTags

  constructor(scope: Construct, id: string, props: CompliantStackProps) {
    super(scope, id, props)

    this.requiredTags = props.requiredTags
    applyRequiredTags(this, props.requiredTags)
  }
}
