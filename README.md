# @ubercode/compliant-constructs

> **Status: pre-alpha (0.1.x).** The API is unstable and the control catalog is incomplete.
> Do not rely on this for an assessment yet.

Compliance-hardened AWS CDK constructs. Same shape as the CDK modules you already use, but the
compliant configuration is the default and the non-compliant one is unrepresentable.

```ts
import * as efs from '@ubercode/compliant-constructs/cmmc2/aws-efs'

// `kmsKey` is required, not optional. `encrypted` cannot be set at all.
// `removalPolicy` accepts RETAIN or SNAPSHOT, and nothing else.
const fs = new efs.FileSystem(this, 'Data', { vpc, vpcSubnets, kmsKey })
```

## Read this before you use it

**Using this library does not make you CMMC compliant.** CMMC Level 2 comprises 110 practices, and
the large majority of them are organizational rather than technical: policy documents, training
records, incident response procedures, media handling, personnel screening. Infrastructure
configuration speaks to a minority of them, and for most of those it provides only part of the
required evidence.

What this library does is narrower and, we think, more honest: it makes the technically-enforceable
subset the default, and it generates a coverage report that states exactly which practices it
addresses, how completely, and what is still owed. That coverage table is generated from the same
metadata that drives the constructs, so it cannot drift into overclaiming.

See [`docs/coverage.md`](docs/coverage.md) once the first constructs land.

## How it works

Three layers, because a typed wrapper on its own is opt-in and bypassable.

| Layer           | Mechanism                                     | Catches                                                       | When    |
| --------------- | --------------------------------------------- | ------------------------------------------------------------- | ------- |
| **Ergonomic**   | narrowed-type construct wrappers              | wrong props on constructs you wrote                           | compile |
| **Enforcement** | [cdk-nag](https://github.com/cdklabs/cdk-nag) | escape hatches, direct imports, constructs you did not author | synth   |
| **Hygiene**     | eslint `no-restricted-imports`                | people routing around the wrappers                            | lint    |

The enforcement layer is cdk-nag's `NIST80053R5Checks`, not a bespoke rule engine. CMMC Level 2
practices derive from NIST SP 800-171 Rev 2, which in turn derives from 800-53, so that pack already
covers most of the ground. This library's own acceptance gate is:

> Every construct here passes `NIST80053R5Checks` with zero suppressions.

## Evidence generation

Constructs record control claims as construct-tree metadata. The `attest` CLI walks a synthesized
cloud assembly, joins those claims against cdk-nag's report, and emits:

- `coverage.md` - practice-by-practice coverage with satisfaction level and caveats
- `evidence.csv` - every claim tied to a construct path and deployed resource
- `untagged.csv` - resources that could not carry the required tags, and why

That last one exists because CDK tagging only reaches CloudFormation-managed resources with a tags
property. Runtime-created resources (EBS volumes an ASG launches, ENIs that ECS creates) never
receive CDK tags at all. Silently omitting them from a scope boundary is worse than documenting the
gap.

## Install

```sh
pnpm add @ubercode/compliant-constructs
```

Peer dependencies: `aws-cdk-lib` (>= 2.165.0), `constructs` (>= 10), `cdk-nag` (>= 3).

## Design notes

- **TypeScript only, no jsii.** jsii forbids generics and union types in exported APIs, which would
  rule out the `Omit<>` and narrowed-union techniques this library is built on. There is no Python
  or .NET distribution and there will not be one.
- **Subpath resolution.** `cdk init app --language typescript` still generates a tsconfig using
  classic node10 module resolution, which ignores the `exports` map. The build emits real stub
  directories at the package root so subpath imports resolve for default CDK projects too.
- **Greenfield.** Adopting the composite constructs changes construct paths, which CloudFormation
  reads as resource replacement. These are for new stacks.

## License

Apache-2.0
