import { Stack } from 'aws-cdk-lib'
import * as iam from 'aws-cdk-lib/aws-iam'
import type * as kms from 'aws-cdk-lib/aws-kms'
import type * as logs from 'aws-cdk-lib/aws-logs'
import * as ssm from 'aws-cdk-lib/aws-ssm'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { LogGroup } from '../aws-logs/index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export interface SessionManagerAccessProps {
  /** Retention for the session transcript log group. Defaults to one year. */
  readonly logRetention?: logs.RetentionDays

  /** Key for the transcripts and the session channel. Defaults to the stack's. */
  readonly encryptionKey?: kms.IKey

  /**
   * Idle timeout in minutes before a session is terminated. Defaults to 15.
   *
   * SC.L2-3.13.9 asks for network connections to be terminated at the end of a
   * session or after a period of inactivity. An administrative session left
   * open on an unattended workstation is exactly what that practice is about.
   * AWS accepts 1 to 60.
   */
  readonly idleSessionTimeoutMinutes?: number
}

/**
 * Administrative access through Systems Manager Session Manager.
 *
 * This is the answer to the remote access practices, and the thing that makes
 * an isolated VPC usable. Sessions run outbound over the SSM endpoints, so
 * there is no bastion, no inbound SSH or RDP rule, and no public IP anywhere
 * in the path.
 *
 * Three practices ask for remote access to be monitored, encrypted, and routed
 * through managed access control points. Session Manager answers all three at
 * once: every session is brokered by AWS, every keystroke and response is
 * written to a log group, and the channel is KMS-encrypted end to end.
 *
 * What this creates is the account-level session preferences document and a
 * role. Attach {@link instanceRole} to instances you want to reach - it carries
 * `AmazonSSMManagedInstanceCore` and nothing else, so an operator can open a
 * session and cannot use the instance profile for anything more.
 *
 * The preferences document is `SSM-SessionManagerRunShell`, which is
 * account-and-region wide rather than per-VPC. Declaring two in one stack
 * throws.
 *
 * **This assumes the SSM endpoints exist.** In an isolated VPC that means
 * `ssm`, `ssmmessages` and `ec2messages` interface endpoints - `CuiVpc`
 * provisions all three by default. Without them the agent cannot reach the
 * service and sessions simply fail to start.
 */
export class SessionManagerAccess extends Construct {
  readonly logGroup: LogGroup
  readonly encryptionKey: kms.IKey
  readonly instanceRole: iam.Role
  readonly preferences: ssm.CfnDocument

  constructor(scope: Construct, id: string, props: SessionManagerAccessProps = {}) {
    super(scope, id)

    // Own props first: a caller who passed something invalid should hear about
    // that rather than about a singleton they did not know existed.
    const idleTimeout = props.idleSessionTimeoutMinutes ?? 15
    if (idleTimeout < 1 || idleTimeout > 60) {
      throw new Error(
        `idleSessionTimeoutMinutes must be between 1 and 60, got ${idleTimeout}. ` +
          'Sessions that never time out are the problem SC.L2-3.13.9 describes.'
      )
    }

    assertSinglePreferencesPerStack(this)

    // Resolved once and used for both the transcript at rest and the session
    // channel itself, so a reader of the evidence report sees one key covering
    // the whole administrative path rather than having to correlate two.
    this.encryptionKey = resolveEncryptionKey(scope, props.encryptionKey)

    this.logGroup = new LogGroup(this, 'SessionLogs', {
      encryptionKey: this.encryptionKey,
      ...(props.logRetention === undefined ? {} : { retention: props.logRetention }),
    })

    this.instanceRole = new iam.Role(this, 'InstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'Allows Session Manager to reach instances, and nothing else',
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(
          this,
          'SsmCore',
          Stack.of(this).formatArn({
            service: 'iam',
            region: '',
            account: 'aws',
            resource: 'policy',
            resourceName: 'AmazonSSMManagedInstanceCore',
          })
        ),
      ],
    })

    this.preferences = new ssm.CfnDocument(this, 'SessionPreferences', {
      // Session Manager only reads preferences from a document with this exact
      // name. Anything else is created successfully and then ignored.
      name: 'SSM-SessionManagerRunShell',
      documentType: 'Session',
      documentFormat: 'JSON',
      updateMethod: 'NewVersion',
      content: {
        schemaVersion: '1.0',
        description: 'Session Manager preferences enforcing logging and encryption',
        sessionType: 'Standard_Stream',
        inputs: {
          cloudWatchLogGroupName: this.logGroup.logGroupName,
          // Streaming means a live session appears in the log as it happens
          // rather than only on clean exit - a session that is killed still
          // leaves a transcript.
          cloudWatchStreamingEnabled: true,
          cloudWatchEncryptionEnabled: true,
          kmsKeyId: this.encryptionKey.keyId,
          idleSessionTimeout: String(idleTimeout),
          shellProfile: { linux: '', windows: '' },
        },
      },
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AC.L2-3.1.12',
        satisfaction: 'partial',
        evidence:
          `Every session is recorded to an encrypted log group with streaming enabled, and idles ` +
          `out after ${idleTimeout} minutes`,
        caveat:
          'Records and time-bounds the sessions. Somebody still has to review the transcripts; ' +
          'monitoring is not the same as recording.',
      }),
      cmmc2Claim({
        practice: 'AC.L2-3.1.13',
        satisfaction: 'partial',
        evidence:
          'Session channel is TLS to the Systems Manager service and the transcript is encrypted ' +
          'at rest with a customer-managed key',
        caveat:
          'Covers the session channel. Whatever the operator does inside the session is beyond ' +
          'its reach.',
      }),
      cmmc2Claim({
        practice: 'AC.L2-3.1.14',
        satisfaction: 'partial',
        evidence:
          'Access is brokered entirely by Systems Manager - no bastion, no inbound SSH or RDP, ' +
          'and no public IP in the path',
        caveat:
          'Systems Manager is the managed access control point for this path. Any other route ' +
          'into the environment is outside what this construct establishes.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.9',
        satisfaction: 'partial',
        evidence: `Idle sessions are terminated after ${idleTimeout} minutes`,
        caveat:
          'Terminates administrative sessions. Application-level sessions have their own ' +
          'timeouts, which this does not touch.',
      }),
      cmmc2Claim({
        practice: 'SC.L2-3.13.3',
        satisfaction: 'supporting',
        evidence:
          'Administrative access travels a separate path from application traffic, over the SSM ' +
          'endpoints rather than any application listener',
        caveat:
          'Separates the management path at the network level. Separating user from ' +
          'administrator functionality inside the application is a design matter.',
      }),
    ])
  }
}

function assertSinglePreferencesPerStack(access: Construct): void {
  const existing = Stack.of(access)
    .node.findAll()
    .filter(c => c !== access && c instanceof SessionManagerAccess)

  if (existing.length > 0) {
    throw new Error(
      'Session Manager preferences are account and region wide, and ' +
        `${existing[0]?.node.path} already declares them in this stack. Reference that one instead.`
    )
  }
}
