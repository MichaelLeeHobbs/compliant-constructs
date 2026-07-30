import { App } from 'aws-cdk-lib'
import * as ec2 from 'aws-cdk-lib/aws-ec2'

/** Real-format IDs: aws-cdk-lib validates these against AWS ID patterns at synth. */
export const PRIVATE_SUBNET_A = 'subnet-0aa11bb22cc33dd01'
export const PUBLIC_SUBNET_A = 'subnet-0aa11bb22cc33dd03'

import { CompliantStack } from '../../src/cmmc2/index.js'

/**
 * A stack with an imported VPC.
 *
 * Imported rather than real so that nothing in these tests creates VPC
 * resources of its own. A `new ec2.Vpc(...)` would bring subnets, route tables
 * and an internet gateway along with it, and the cdk-nag findings for those
 * would drown out the ones we are actually asserting about.
 */
export function testStack(id = 'TestStack'): {
  app: App
  stack: CompliantStack
  vpc: ec2.IVpc
} {
  const app = new App()
  const stack = new CompliantStack(app, id, {
    env: { account: '111111111111', region: 'us-east-1' },
    requiredTags: {
      project: 'vanguard',
      owner: 'platform-team',
      environment: 'prod',
      containsCui: true,
    },
  })

  const vpc = ec2.Vpc.fromVpcAttributes(stack, 'Vpc', {
    vpcId: 'vpc-0aa11bb22cc33dd44',
    availabilityZones: ['us-east-1a', 'us-east-1b'],
    privateSubnetIds: [PRIVATE_SUBNET_A, 'subnet-0aa11bb22cc33dd02'],
    privateSubnetRouteTableIds: ['rtb-0aa11bb22cc33dd01', 'rtb-0aa11bb22cc33dd02'],
    publicSubnetIds: [PUBLIC_SUBNET_A, 'subnet-0aa11bb22cc33dd04'],
    publicSubnetRouteTableIds: ['rtb-0aa11bb22cc33dd03', 'rtb-0aa11bb22cc33dd04'],
  })

  return { app, stack, vpc }
}
