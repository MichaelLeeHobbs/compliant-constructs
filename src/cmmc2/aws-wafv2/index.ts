import * as wafv2 from 'aws-cdk-lib/aws-wafv2'
import { Construct } from 'constructs'

import { addControlClaims } from '../../index.js'
import { cmmc2Claim } from '../index.js'

/**
 * AWS managed rule groups applied by default.
 *
 * The common rule set and known-bad-inputs cover the OWASP-style attacks any
 * internet-facing listener sees within minutes of going up. The IP reputation
 * list costs nothing extra and removes a large share of automated traffic
 * before the other rules have to evaluate it.
 */
const DEFAULT_MANAGED_RULES = [
  'AWSManagedRulesCommonRuleSet',
  'AWSManagedRulesKnownBadInputsRuleSet',
  'AWSManagedRulesAmazonIpReputationList',
] as const

export interface WebAclProps {
  /**
   * Managed rule groups to apply, in order. Defaults to the common set,
   * known bad inputs, and the IP reputation list.
   */
  readonly managedRuleGroups?: readonly string[]

  /**
   * Where this ACL will be attached.
   *
   * `REGIONAL` for an application load balancer or API Gateway, `CLOUDFRONT`
   * for a distribution. A CloudFront ACL must live in us-east-1 regardless of
   * where the rest of the stack is.
   */
  readonly scope: 'REGIONAL' | 'CLOUDFRONT'

  /** Name for the ACL and its CloudWatch metrics. */
  readonly name: string
}

/**
 * A WAF web ACL that blocks by exception rather than counting.
 *
 * The default action is `allow` with managed rule groups blocking matches -
 * the standard shape for a web ACL in front of an application. What this
 * construct will not let you do is deploy the rule groups in count-only mode,
 * which is a common way to end up with a web ACL that reports attacks and
 * stops none of them.
 *
 * Attach it to an `ApplicationLoadBalancer` to clear `ALBWAFEnabled`, which is
 * otherwise outstanding for every load balancer this library creates.
 *
 * Logging is not configured here. WAF logging needs a destination whose name
 * begins with `aws-waf-logs-`, and putting request logs somewhere depends on
 * how long you want them and who reads them - so it is a deliberate step
 * rather than a default. `WAFv2LoggingEnabled` stays outstanding until you
 * take it.
 */
export class WebAcl extends Construct {
  readonly webAcl: wafv2.CfnWebACL

  constructor(scope: Construct, id: string, props: WebAclProps) {
    super(scope, id)

    const groups = props.managedRuleGroups ?? DEFAULT_MANAGED_RULES

    this.webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: props.name,
      scope: props.scope,
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: props.name,
        sampledRequestsEnabled: true,
      },
      rules: groups.map((group, index) => ({
        name: group,
        priority: index,
        statement: {
          managedRuleGroupStatement: { vendorName: 'AWS', name: group },
        },
        // No overrideAction: none - that is what turns a rule group into
        // count-only mode and produces a web ACL that blocks nothing.
        overrideAction: { none: {} },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: group,
          sampledRequestsEnabled: true,
        },
      })),
    })

    addControlClaims(this, [
      cmmc2Claim({
        practice: 'SC.L2-3.13.1',
        satisfaction: 'partial',
        evidence: `Web ACL blocking matches from ${groups.length} AWS managed rule groups`,
        nagRuleIds: ['NIST.800.53.R5-ALBWAFEnabled'],
        caveat:
          'Inspects HTTP requests at the boundary. It does not see traffic that reaches the ' +
          'application by another path, nor anything above the request layer.',
      }),
      cmmc2Claim({
        practice: 'SI.L2-3.14.1',
        satisfaction: 'supporting',
        evidence:
          'AWS managed rule groups are updated by AWS as new attack patterns appear, without a ' +
          'deployment on your side',
        caveat:
          'Mitigates known request-layer attacks. Identifying and correcting flaws in your own ' +
          'code is a separate process.',
      }),
    ])
  }

  /** Associate this ACL with a regional resource, such as a load balancer. */
  associateWith(id: string, resourceArn: string): wafv2.CfnWebACLAssociation {
    if (this.webAcl.scope !== 'REGIONAL') {
      throw new Error(
        'only a REGIONAL web ACL can be associated with a load balancer or API. A CLOUDFRONT ' +
          'ACL is attached through the distribution instead.'
      )
    }

    return new wafv2.CfnWebACLAssociation(this, id, {
      resourceArn,
      webAclArn: this.webAcl.attrArn,
    })
  }
}
