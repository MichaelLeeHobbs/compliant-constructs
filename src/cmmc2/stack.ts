import { RemovalPolicy, Stack, type StackProps } from 'aws-cdk-lib'
import * as kms from 'aws-cdk-lib/aws-kms'
import { type Construct, type IConstruct } from 'constructs'

import { applyRequiredTags, type RequiredTags } from '../tagging.js'

/** Construct id of the key a {@link CompliantStack} creates for itself. */
export const DEFAULT_ENCRYPTION_KEY_ID = 'DefaultEncryptionKey'

/**
 * Marker used instead of `instanceof` to recognise a {@link CompliantStack}.
 *
 * This package ships one bundle per subpath with code splitting off, so
 * `cmmc2/index.js` and `cmmc2/patterns/index.js` each carry their own copy of
 * this module - and therefore their own `CompliantStack` class. A stack created
 * from one entry point is not `instanceof` the class from the other, so
 * importing the stack from `cmmc2` and a pattern from `cmmc2/patterns` (which
 * is what the README tells people to do) would fail an `instanceof` check.
 *
 * `Symbol.for` resolves to the same symbol across every copy, which is why the
 * CDK itself uses this pattern for `Construct.isConstruct` and friends.
 */
const COMPLIANT_STACK_SYMBOL = Symbol.for('@ubercode/compliant-constructs.CompliantStack')

export interface CompliantStackProps extends Omit<StackProps, 'tags'> {
  /**
   * Tags applied to every resource in the stack.
   *
   * Required and typed, replacing `StackProps.tags`. A free-form tag map makes
   * it possible to deploy a stack holding CUI with no indication that it does,
   * which is precisely the thing an assessment scope boundary has to answer.
   */
  readonly requiredTags: RequiredTags

  /**
   * Key used by constructs in this stack that do not bring their own.
   *
   * Defaults to a rotating customer-managed key created here on first use. Pass
   * one to share a key across stacks, or to keep key custody somewhere else.
   */
  readonly encryptionKey?: kms.IKey
}

/**
 * A stack whose resources are tagged for assessment scoping and encrypted with
 * a customer-managed key by construction.
 *
 * The key is stack-scoped by default rather than per-resource, so that the
 * cryptographic boundary lines up with the scope boundary the `containsCui` tag
 * already draws. "Everything encrypted by this key is in this scope" is a much
 * easier statement to evidence than reconciling a pile of keys against a
 * resource inventory. Individual constructs can still override it where
 * something needs its own lifetime - a bucket shared with an outside party, or
 * data with a different revocation schedule.
 *
 * The trade-off is blast radius: one key per stack means a compromise,
 * accidental deletion, or key-policy mistake reaches everything in it. The
 * per-resource override is the answer where that matters.
 *
 * Deliberately does not register cdk-nag itself. Wiring a validation plugin
 * from a stack constructor would be surprising, would fire once per stack, and
 * `Validations.of()` does not exist at this library's peer floor. Applications
 * should wire the pack in at the app level:
 *
 * ```ts
 * Validations.of(app).addPlugins(new NIST80053R5Checks(app))
 * ```
 */
export class CompliantStack extends Stack {
  /** The tags applied to this stack, readable by constructs within it. */
  readonly requiredTags: RequiredTags

  private resolvedEncryptionKey: kms.IKey | undefined

  constructor(scope: Construct, id: string, props: CompliantStackProps) {
    super(scope, id, props)

    this.requiredTags = props.requiredTags
    this.resolvedEncryptionKey = props.encryptionKey

    Object.defineProperty(this, COMPLIANT_STACK_SYMBOL, { value: true })

    applyRequiredTags(this, props.requiredTags)
  }

  /**
   * Whether a construct is a {@link CompliantStack}, across bundle copies.
   *
   * Prefer this to `instanceof` for the reason described on
   * {@link COMPLIANT_STACK_SYMBOL}.
   */
  static isCompliantStack(x: unknown): x is CompliantStack {
    return typeof x === 'object' && x !== null && COMPLIANT_STACK_SYMBOL in x
  }

  /**
   * The stack's default encryption key, created on first access.
   *
   * Lazy so that a stack with no encrypted resources does not provision a key
   * nobody uses. The key policy is CDK's default, which delegates authorisation
   * to IAM rather than enumerating principals - services that additionally
   * require a key-policy statement of their own (CloudWatch Logs, notably) add
   * it when they attach.
   */
  get encryptionKey(): kms.IKey {
    this.resolvedEncryptionKey ??= new kms.Key(this, DEFAULT_ENCRYPTION_KEY_ID, {
      description: `Default CUI encryption key for ${this.stackName}`,
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    })

    return this.resolvedEncryptionKey
  }

  /**
   * Find the {@link CompliantStack} a construct belongs to.
   *
   * Throws rather than inventing a key if the construct is in a plain
   * `cdk.Stack`. Silently creating one would quietly undo the guarantee that
   * made the key mandatory in the first place.
   */
  static of(construct: IConstruct): CompliantStack {
    const stack = Stack.of(construct)

    if (!CompliantStack.isCompliantStack(stack)) {
      throw new Error(
        `${construct.node.path} needs an encryption key, but its stack "${stack.stackName}" is a ` +
          'plain cdk.Stack. Either use CompliantStack, which supplies one, or pass an ' +
          'encryption key to this construct explicitly.'
      )
    }

    return stack
  }
}

/**
 * Resolve the key a construct should use: its own if supplied, otherwise the
 * one belonging to its {@link CompliantStack}.
 *
 * A customer-managed key is always used. What changed when this became optional
 * is only whether the caller has to restate it.
 */
export function resolveEncryptionKey(scope: IConstruct, provided?: kms.IKey): kms.IKey {
  return provided ?? CompliantStack.of(scope).encryptionKey
}
