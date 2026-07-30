import { CfnResource, TagManager, Tags } from 'aws-cdk-lib'
import { type IConstruct } from 'constructs'

/**
 * Tags every resource in a compliant stack must carry.
 *
 * Typed and required rather than a free-form map, because these are not
 * cosmetic: `containsCui` is the machine-readable form of the assessment scope
 * boundary, and an assessor asking "which resources hold CUI?" should be
 * answerable from tags rather than from a diagram someone drew once.
 */
export interface RequiredTags {
  /** Owning project or system name. */
  readonly project: string
  /** Team or individual accountable for the resource. */
  readonly owner: string
  /** Deployment environment, e.g. `'prod'`. */
  readonly environment: string
  /** Whether this resource stores, processes, or transmits CUI. */
  readonly containsCui: boolean
}

/** Tag keys written by {@link applyRequiredTags}. */
export const REQUIRED_TAG_KEYS = ['Project', 'Owner', 'Environment', 'ContainsCui'] as const

/**
 * Apply the required tags to a scope.
 *
 * CDK tags inherit down the construct tree, so applying these once at the
 * stack covers everything beneath it that can carry tags. What it cannot cover
 * is the subject of {@link findUntaggableResources}.
 */
export function applyRequiredTags(scope: IConstruct, tags: RequiredTags): void {
  Tags.of(scope).add('Project', tags.project)
  Tags.of(scope).add('Owner', tags.owner)
  Tags.of(scope).add('Environment', tags.environment)
  Tags.of(scope).add('ContainsCui', String(tags.containsCui))
}

/** A resource that cannot carry CDK tags, and where it sits in the tree. */
export interface UntaggableResource {
  /** Construct path, e.g. `'MyStack/Storage/FileSystem/EfsMountTarget1'`. */
  readonly path: string
  /** CloudFormation resource type, e.g. `'AWS::EFS::MountTarget'`. */
  readonly cfnType: string
}

/**
 * Find every resource at or below `root` that cannot receive the required tags.
 *
 * CDK's tagging is itself an aspect, and it can only set tags on L1 resources
 * whose CloudFormation type actually has a tags property. Anything else is
 * silently skipped today, which is the problem: a resource missing from a
 * scope boundary because nothing could tag it looks identical to one that was
 * never in scope.
 *
 * This does not fix the gap - nothing can, from CDK - but it converts it from
 * invisible into a reviewable list that the evidence report can carry.
 *
 * Note this covers only resources CloudFormation manages. Resources created at
 * runtime by a service (EBS volumes an Auto Scaling group launches, ENIs that
 * ECS attaches) are never in the construct tree at all, and need service-level
 * tag propagation instead.
 */
export function findUntaggableResources(root: IConstruct): UntaggableResource[] {
  const found: UntaggableResource[] = []

  for (const construct of root.node.findAll()) {
    if (!CfnResource.isCfnResource(construct)) continue
    if (TagManager.isTaggable(construct)) continue

    found.push({ path: construct.node.path, cfnType: construct.cfnResourceType })
  }

  return found
}
