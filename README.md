# @ubercode/compliant-constructs

> **Status: pre-alpha (0.1.x).** The API is unstable and the control catalog is incomplete.
> Do not rely on this for an assessment yet.

Compliance-hardened AWS CDK constructs. Same shape as the CDK modules you already use, but the
compliant configuration is the default and the non-compliant one is unrepresentable.

```ts
import * as efs from '@ubercode/compliant-constructs/cmmc2/aws-efs'

// `kmsKey` and `vpcSubnets` are required, where the CDK makes them optional.
// `encrypted`, `allowAnonymousAccess`, `enableAutomaticBackups` and
// `fileSystemPolicy` cannot be set at all - the construct owns them.
// `removalPolicy` accepts only RETAIN or RETAIN_ON_UPDATE_OR_DELETE.
const fs = new efs.FileSystem(this, 'Data', { vpc, vpcSubnets, kmsKey })
```

Or take the whole compliant arrangement, which adds the pieces a file system cannot provide for
itself - a rotating customer-managed key, a default-deny security group, and enrolment in an AWS
Backup plan writing to an encrypted vault:

```ts
import { CompliantStack } from '@ubercode/compliant-constructs/cmmc2'
import { EncryptedFileSystem } from '@ubercode/compliant-constructs/cmmc2/patterns'

const stack = new CompliantStack(app, 'Storage', {
  // Typed and required, replacing StackProps.tags. `containsCui` is the
  // machine-readable form of your assessment scope boundary.
  requiredTags: { project: 'vanguard', owner: 'platform', environment: 'prod', containsCui: true },
})

new EncryptedFileSystem(stack, 'Cui', { vpc, vpcSubnets, fileSystemName: 'vanguard-cui' })
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
covers most of the ground.

Wire it in at the app level, where it fails your build. Note that cdk-nag v3 is a CDK policy
validation plugin, not an Aspect - `Aspects.of(app).add(...)` was the v2 API:

```ts
import { Validations } from 'aws-cdk-lib'
import { NIST80053R5Checks } from 'cdk-nag'

Validations.of(app).addPlugins(new NIST80053R5Checks(app))
```

This library's own acceptance gate is:

> Every construct here passes `NIST80053R5Checks` with zero suppressions.

`EncryptedFileSystem` meets that, and there is a test asserting it. The 1:1 `FileSystem` wrapper
cannot: `EFSInBackupPlan` wants an `AWS::Backup::BackupSelection`, and a drop-in replacement for
`efs.FileSystem` has no business creating resources the construct it replaces does not. Its one
outstanding finding is pinned by a test, so a future cdk-nag adding an EFS rule fails the build here
rather than surfacing in your audit.

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

Peer dependencies: `aws-cdk-lib` (>= 2.257.0) and `constructs` (>= 10).

`cdk-nag` (>= 3) is an **optional** peer, needed only for the `/verify` subpath and for wiring the
rule pack into your own app. The constructs themselves have no dependency on it. The 2.257.0 floor
is set by cdk-nag v3, which requires it; the constructs alone work on older CDK, but that is not a
combination this project's own test suite can exercise, so it is not a compatibility claim we make.

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
