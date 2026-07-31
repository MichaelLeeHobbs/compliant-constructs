import { Match, Template } from 'aws-cdk-lib/assertions'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as ecs from 'aws-cdk-lib/aws-ecs'

import { collectControlClaims } from '../src/index.js'
import { verifyCompliance } from '../src/verify.js'
import { Vpc } from '../src/cmmc2/aws-ec2/index.js'
import { Cluster, FargateService, FargateTaskDefinition } from '../src/cmmc2/aws-ecs/index.js'
import { LogGroup } from '../src/cmmc2/aws-logs/index.js'
import { testStack } from './helpers/fixtures.js'

const IMAGE = ecs.ContainerImage.fromRegistry('public.ecr.aws/nginx/nginx:latest')

describe('Vpc', () => {
  it('enables flow logs for all traffic to an encrypted log group', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', { maxAzs: 2 })
    const template = Template.fromStack(stack)

    template.hasResourceProperties('AWS::EC2::FlowLog', { TrafficType: 'ALL' })
    template.hasResourceProperties('AWS::Logs::LogGroup', { KmsKeyId: Match.anyValue() })
  })

  /**
   * mapPublicIpOnLaunch defaults to true on public subnets, so anything landing
   * there gets a routable address whether or not anyone intended it.
   */
  it('stops public subnets auto-assigning public IPs', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', { maxAzs: 2 })

    const subnets = Template.fromStack(stack).findResources('AWS::EC2::Subnet')
    const mapped = Object.values(subnets).filter(
      s => (s.Properties as { MapPublicIpOnLaunch?: boolean }).MapPublicIpOnLaunch === true
    )

    expect(mapped).toHaveLength(0)
  })

  it('strips the default security group', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', { maxAzs: 2 })

    // CDK implements this with a custom resource rather than a property.
    Template.fromStack(stack).resourceCountIs('Custom::VpcRestrictDefaultSG', 1)
  })

  it('accepts a supplied flow log group instead of creating one', () => {
    const { stack } = testStack()
    const shared = new LogGroup(stack, 'SharedFlowLogs')
    const vpc = new Vpc(stack, 'Net', { maxAzs: 2, flowLogGroup: shared })

    expect(vpc.flowLogGroup).toBe(shared)
    Template.fromStack(stack).resourceCountIs('AWS::Logs::LogGroup', 1)
  })

  /**
   * A public subnet is by definition one with a default route to an internet
   * gateway, so this cannot be cleared while public subnets exist. Pinned so
   * that any *other* VPC finding appearing later fails the build.
   */
  it('leaves only the internet-gateway route finding when public subnets exist', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', { maxAzs: 2 })

    const vpcFindings = verifyCompliance(stack)
      .violations.map(v => v.ruleId)
      .filter(id => id.includes('VPC'))

    expect(vpcFindings).toEqual(['NIST.800.53.R5-VPCNoUnrestrictedRouteToIGW'])
  })

  it('has no VPC findings at all when built with private subnets only', () => {
    const { stack } = testStack()
    new Vpc(stack, 'Net', {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'isolated', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
      ],
    })

    const vpcFindings = verifyCompliance(stack)
      .violations.map(v => v.ruleId)
      .filter(id => id.includes('VPC'))

    expect(vpcFindings).toEqual([])
  })
})

describe('Cluster', () => {
  it('enables Container Insights', () => {
    const { stack, vpc } = testStack()
    new Cluster(stack, 'C', { vpc })

    Template.fromStack(stack).hasResourceProperties('AWS::ECS::Cluster', {
      ClusterSettings: Match.arrayWith([{ Name: 'containerInsights', Value: 'enabled' }]),
    })
  })
})

describe('FargateTaskDefinition', () => {
  function subject() {
    const { stack } = testStack()
    const logGroup = new LogGroup(stack, 'TaskLogs')
    const td = new FargateTaskDefinition(stack, 'Td', { cpu: 256, memoryLimitMiB: 512 })
    td.addComplianceContainer('app', {
      image: IMAGE,
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'app', logGroup }),
    })
    return { stack, td }
  }

  it('runs containers read-only and unprivileged', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: Match.arrayWith([
        Match.objectLike({ ReadonlyRootFilesystem: true, Privileged: false }),
      ]),
    })
  })

  it('configures a log driver', () => {
    const { stack } = subject()

    Template.fromStack(stack).hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: Match.arrayWith([
        Match.objectLike({ LogConfiguration: Match.objectLike({ LogDriver: 'awslogs' }) }),
      ]),
    })
  })

  it('records claims against the container, not just the task definition', () => {
    const { td } = subject()
    const ids = collectControlClaims(td)
      .map(c => c.claim.controlId)
      .sort()

    expect(ids).toEqual(['AU.L2-3.3.1', 'CM.L2-3.4.6'])
  })
})

describe('FargateService', () => {
  it('never assigns a public IP', () => {
    const { stack, vpc } = testStack()
    const logGroup = new LogGroup(stack, 'TaskLogs')
    const cluster = new Cluster(stack, 'C', { vpc })
    const td = new FargateTaskDefinition(stack, 'Td', { cpu: 256, memoryLimitMiB: 512 })
    td.addComplianceContainer('app', {
      image: IMAGE,
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'app', logGroup }),
    })
    // aws-cdk-lib declares several optional members differently on classes and
    // their interfaces, which only conflicts under exactOptionalPropertyTypes.
    new FargateService(stack, 'Svc', { cluster: cluster as ecs.ICluster, taskDefinition: td })

    Template.fromStack(stack).hasResourceProperties('AWS::ECS::Service', {
      NetworkConfiguration: Match.objectLike({
        AwsvpcConfiguration: Match.objectLike({ AssignPublicIp: 'DISABLED' }),
      }),
    })
  })
})
