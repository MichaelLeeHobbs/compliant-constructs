import * as ecs from 'aws-cdk-lib/aws-ecs'
import { type Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/** Props each wrapper takes ownership of. */
type MandatedClusterProps = 'containerInsightsV2'
type MandatedServiceProps = 'assignPublicIp'
type MandatedContainerProps = 'readonlyRootFilesystem' | 'privileged' | 'logging'

/** Fail to compile if any mandated prop stops existing upstream. */
type _ClusterCanary = MandatedClusterProps extends keyof ecs.ClusterProps ? true : never
type _ServiceCanary = MandatedServiceProps extends keyof ecs.FargateServiceProps ? true : never
type _ContainerCanary = MandatedContainerProps extends keyof ecs.ContainerDefinitionOptions
  ? true
  : never
const _canaries: [_ClusterCanary, _ServiceCanary, _ContainerCanary] = [true, true, true]
void _canaries

export type ClusterProps = Omit<ecs.ClusterProps, MandatedClusterProps>

/**
 * An ECS cluster configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `ecs.Cluster` with Container Insights on. Without
 * it there is no record of task-level resource behaviour, which is the only
 * signal that distinguishes a busy service from a compromised one.
 */
export class Cluster extends ecs.Cluster {
  constructor(scope: Construct, id: string, props: ClusterProps = {}) {
    super(scope, id, {
      ...props,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SI.L2-3.14.6',
        satisfaction: 'supporting',
        evidence: 'Container Insights enabled, emitting task and container level metrics',
        caveat:
          'Produces the telemetry. Monitoring for attacks means someone alerting on it, which is ' +
          'not something a cluster can do for you.',
      }),
    ])
  }
}

export interface ContainerOptions extends Omit<ecs.ContainerDefinitionOptions, MandatedContainerProps> {
  /**
   * Log configuration. Required.
   *
   * A container with no log driver writes to nowhere. Whatever it observed is
   * gone the moment the task stops, which makes AU.L2-3.3.1 unanswerable for
   * everything running inside it.
   */
  readonly logging: ecs.LogDriver
}

/**
 * A Fargate task definition configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `ecs.FargateTaskDefinition`. Containers added
 * through {@link FargateTaskDefinition.addContainer} run with a read-only root
 * filesystem, cannot be privileged, and must have a log driver.
 *
 * The read-only root filesystem is the one that changes behaviour most. It
 * stops a process that has been compromised from persisting anything to the
 * image layer, which turns a container breakout into something that dies with
 * the task. Mount a volume for the paths that genuinely need to be writable.
 */
export class FargateTaskDefinition extends ecs.FargateTaskDefinition {
  /**
   * Add a container, with the hardening this library mandates.
   *
   * Deliberately narrower than the method it overrides: `readonlyRootFilesystem`
   * and `privileged` are not yours to set, and `logging` is required.
   *
   * This overrides `addContainer` rather than sitting alongside it. An earlier
   * version added a separate `addComplianceContainer` and left the inherited
   * method untouched, which meant `addContainer` silently accepted
   * `privileged: true` with a writable root and no logging - a complete bypass
   * of everything this class exists to enforce, reachable by using the more
   * obvious method name.
   */
  override addContainer(id: string, options: ContainerOptions): ecs.ContainerDefinition {
    // Runtime check as well as the type: JavaScript callers, and anything
    // reaching this through the base class signature, get the same guarantee.
    if (options.logging === undefined) {
      throw new Error(
        `container "${id}" needs a log driver. Without one it writes nowhere, and whatever it ` +
          'observed is gone when the task stops. Pass logging: ecs.LogDrivers.awsLogs({ ... }).'
      )
    }

    const container = super.addContainer(id, {
      ...options,
      readonlyRootFilesystem: true,
      privileged: false,
      logging: options.logging,
    })

    addControlClaims(container, [
      cmmc2Claim({
        practice: 'CM.L2-3.4.6',
        satisfaction: 'partial',
        evidence: 'ReadonlyRootFilesystem=true and Privileged=false',
        caveat:
          'Removes write access to the image layer and host-level privilege. The packages inside ' +
          'the image, and what the process is allowed to reach over the network, are elsewhere.',
      }),
      cmmc2Claim({
        practice: 'AU.L2-3.3.1',
        satisfaction: 'partial',
        evidence: 'Container has a log driver configured',
        caveat:
          'Captures what the process writes to stdout and stderr. Whether that is enough to ' +
          'investigate unauthorised activity is a property of the application.',
      }),
    ])

    return container
  }
}

export type FargateServiceProps = Omit<ecs.FargateServiceProps, MandatedServiceProps>

/**
 * A Fargate service configured for CMMC 2.0 Level 2.
 *
 * A drop-in replacement for `ecs.FargateService` whose tasks never receive a
 * public IP. Reach them through a load balancer or a NAT gateway instead, so
 * that inbound connectivity is something you configured rather than something
 * the default handed out.
 */
export class FargateService extends ecs.FargateService {
  constructor(scope: Construct, id: string, props: FargateServiceProps) {
    super(scope, id, {
      ...props,
      assignPublicIp: false,
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'AC.L2-3.1.3',
        satisfaction: 'partial',
        evidence: 'AssignPublicIp=false, so tasks are not directly addressable from the internet',
        caveat:
          'Removes direct inbound reachability. Flow control still depends on the security ' +
          'groups and subnets the service runs in.',
      }),
    ])
  }
}
