import type * as kms from 'aws-cdk-lib/aws-kms'
import * as lambda from 'aws-cdk-lib/aws-lambda'
import type * as logs from 'aws-cdk-lib/aws-logs'
import { type Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

/** Props this wrapper takes ownership of. */
type MandatedProps = 'environmentEncryption' | 'tracing' | 'logGroup'

/** Fails to compile if any mandated prop stops existing on the upstream type. */
type _MandatedPropsExistUpstream = MandatedProps extends keyof lambda.FunctionProps ? true : never
const _canary: _MandatedPropsExistUpstream = true
void _canary

export interface FunctionProps extends Omit<lambda.FunctionProps, MandatedProps> {
  /**
   * Log group for the function. Required.
   *
   * Left to itself, Lambda creates `/aws/lambda/<name>` on first invocation.
   * That log group is never in your template, so it is never tagged, never
   * encrypted with your key, and never given a retention period - it keeps
   * whatever it captured forever, outside the scope boundary entirely. Making
   * it explicit is the only way to bring it inside.
   *
   * Use `LogGroup` from `cmmc2/aws-logs`, or `SecureFunction` from
   * `cmmc2/patterns`, which creates one.
   */
  readonly logGroup: logs.ILogGroup

  /** Key for environment variable encryption. Defaults to the stack's key. */
  readonly environmentEncryption?: kms.IKey

  /** X-Ray tracing. Defaults to `ACTIVE`; `DISABLED` is not representable. */
  readonly tracing?: lambda.Tracing.ACTIVE | lambda.Tracing.PASS_THROUGH
}

/**
 * A Lambda function configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `lambda.Function`. Environment variables are
 * encrypted with a customer-managed key, tracing is on, and the log group is an
 * explicit resource rather than one Lambda quietly creates outside your stack.
 *
 * **Four cdk-nag findings are outstanding, three of them contextual:**
 *
 * - `IAMNoInlinePolicy` is structural. The CDK attaches VPC, DLQ and log
 *   permissions to the execution role it generates as an inline policy, and
 *   avoiding that means taking over role creation entirely - which would make
 *   this something other than a drop-in replacement. Pass your own `role` if
 *   your organisation requires managed policies.
 * - `LambdaInsideVPC` clears when you pass `vpc`. It is not mandated because
 *   plenty of functions have no business in a VPC, and putting one there adds
 *   cold-start latency and usually a NAT gateway bill.
 * - `LambdaDLQ` clears when you pass `deadLetterQueue`, which `SecureFunction`
 *   does for you.
 * - `LambdaConcurrency` clears when you set `reservedConcurrentExecutions`. It
 *   is not mandated because reserved concurrency is drawn from a fixed
 *   account-wide pool of 1000, of which 100 must stay unreserved - so a library
 *   that set it on every function would break deployments at scale. Pick the
 *   functions where throttling protection matters.
 *
 * All four are visible in the generated evidence report rather than suppressed,
 * so the coverage document reflects what is actually configured.
 */
export class Function extends lambda.Function {
  constructor(scope: Construct, id: string, props: FunctionProps) {
    super(scope, id, {
      ...props,
      environmentEncryption: resolveEncryptionKey(scope, props.environmentEncryption),
      tracing: props.tracing ?? lambda.Tracing.ACTIVE,
      logGroup: props.logGroup,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Environment variables encrypted with a customer-managed KMS key',
        caveat:
          'Covers configuration held on the function. Does not cover data the function reads or ' +
          'writes at runtime, nor the deployment package itself.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence:
          'Logs written to an explicit log group with a retention period, rather than one Lambda ' +
          'creates outside the stack; X-Ray tracing enabled',
        caveat:
          'Produces invocation records and traces. Whether the function logs enough to ' +
          'investigate unauthorised activity is a property of its code.',
      }),
      cmmc2Claim({
        practice: 'CM.L2-3.4.1',
        satisfaction: 'supporting',
        evidence: 'Log group is a declared resource, so it appears in the deployed inventory',
        caveat:
          'A function whose log group is implicit is invisible to any inventory built from ' +
          'CloudFormation. Declaring it is a precondition for a baseline, not a baseline itself.',
      }),
    ])
  }
}
