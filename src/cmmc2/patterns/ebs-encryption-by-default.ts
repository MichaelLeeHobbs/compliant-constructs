import { Stack } from 'aws-cdk-lib'
import * as cr from 'aws-cdk-lib/custom-resources'
import * as iam from 'aws-cdk-lib/aws-iam'
import type * as kms from 'aws-cdk-lib/aws-kms'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'
import { resolveEncryptionKey } from '../stack.js'

export interface EbsEncryptionByDefaultProps {
  /**
   * Key used for volumes created without one specified. Defaults to the
   * stack's key.
   */
  readonly encryptionKey?: kms.IKey
}

/**
 * Turn on EBS encryption by default for the account and region.
 *
 * Every EBS volume created afterwards is encrypted whether or not whoever
 * created it asked for encryption - including volumes made outside
 * CloudFormation, by an autoscaling group, or by somebody in the console.
 * That last part is why it is worth having: the wrappers in this library can
 * only govern volumes they create.
 *
 * **This uses a custom resource, because AWS exposes no CloudFormation
 * resource for it.** `EnableEbsEncryptionByDefault` and
 * `ModifyEbsDefaultKmsKeyId` are API calls only. The setting is account and
 * region wide and persists after the stack is deleted - removing this
 * construct does not turn encryption back off, which is the safe direction for
 * a control to fail in.
 *
 * The custom resource brings a Lambda whose execution role uses an inline
 * policy, so `IAMNoInlinePolicy` is outstanding against it. That is the CDK's
 * `AwsCustomResource` machinery rather than anything this construct chooses.
 */
export class EbsEncryptionByDefault extends Construct {
  readonly encryptionKey: kms.IKey

  constructor(scope: Construct, id: string, props: EbsEncryptionByDefaultProps = {}) {
    super(scope, id)

    assertSingleSettingPerStack(this)

    this.encryptionKey = resolveEncryptionKey(scope, props.encryptionKey)
    const region = Stack.of(this).region

    new cr.AwsCustomResource(this, 'EnableEncryption', {
      onUpdate: {
        service: 'EC2',
        action: 'enableEbsEncryptionByDefault',
        // Region-scoped, so a change of region has to re-apply it.
        physicalResourceId: cr.PhysicalResourceId.of(`ebs-encryption-by-default-${region}`),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['ec2:EnableEbsEncryptionByDefault', 'ec2:GetEbsEncryptionByDefault'],
          resources: ['*'],
        }),
      ]),
    })

    new cr.AwsCustomResource(this, 'SetDefaultKey', {
      onUpdate: {
        service: 'EC2',
        action: 'modifyEbsDefaultKmsKeyId',
        parameters: { KmsKeyId: this.encryptionKey.keyArn },
        physicalResourceId: cr.PhysicalResourceId.of(`ebs-default-key-${region}`),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['ec2:ModifyEbsDefaultKmsKeyId', 'ec2:GetEbsDefaultKmsKeyId'],
          resources: ['*'],
        }),
        new iam.PolicyStatement({
          actions: ['kms:DescribeKey'],
          resources: [this.encryptionKey.keyArn],
        }),
      ]),
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence:
          'EBS encryption by default enabled account-wide with a customer-managed key, so every ' +
          'volume created afterwards is encrypted regardless of how it was created',
        caveat:
          'Applies to volumes created after this is enabled, in this region. Volumes that already ' +
          'exist unencrypted stay that way until they are snapshotted and restored.',
      }),
      cmmc2Claim({
        practice: 'MP.L2-3.8.9',
        satisfaction: 'supporting',
        evidence: 'Snapshots inherit encryption from the volume they are taken from',
        caveat:
          'Covers snapshots of encrypted volumes. Snapshots copied to another region or shared ' +
          'with another account need their own key arrangements.',
      }),
    ])
  }
}

function assertSingleSettingPerStack(setting: Construct): void {
  const existing = Stack.of(setting)
    .node.findAll()
    .filter(c => c !== setting && c instanceof EbsEncryptionByDefault)

  if (existing.length > 0) {
    throw new Error(
      'EBS encryption by default is an account and region setting, and ' +
        `${existing[0]?.node.path} already declares it in this stack. Reference that one instead.`
    )
  }
}
