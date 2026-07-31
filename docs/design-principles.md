# Design principles

> The goal is that a non-compliant resource should be **hard to express** — not merely discouraged,
> and not caught later by a linter, but absent from the API you are handed.

Every optional property this library leaves open is a way to build something non-compliant. So the
default answer to "should the caller be able to set this?" is **no, the construct owns it**, and
anything else needs a reason written down.

These are the rules the existing constructs follow. They are here so the next one follows them too,
and so that a reviewer has something concrete to hold a change against.

---

## 1. Prefer unrepresentable over discouraged

Rank the options in this order, and take the highest one that fits:

| Rank | Mechanism | Example |
| ---- | ---------------------------------- | ------------------------------------------------------- |
| 1 | `Omit` the prop entirely | `encrypted` on `FileSystem` — cannot be set at all |
| 2 | Narrow the type to legal values | `removalPolicy` on `Bucket` — `RETAIN` or nothing else |
| 3 | Re-require what the CDK made optional | `vpcSubnets` on `FileSystem` |
| 4 | Runtime check in the constructor | subnets must not be public — no type can express that |
| 5 | Leave it open and record a caveat | reserved concurrency on `Function` |

Drop a rank only when the one above is impossible, and say why in the docstring. Most CDK
enum-likes are classes rather than TypeScript enums, so rank 2 often is not available; that is a
reason to fall to rank 4, not to rank 5.

**Mandates go after the spread.** `super(scope, id, { ...props, encrypted: true })` — never before.
A caller who casts away the types still gets a compliant resource. There is a test for this.

## 2. Narrowing is per-resource, not per-library

`AWS::RDS::DBInstance` accepts a `Snapshot` deletion policy. `AWS::S3::Bucket`, `AWS::EFS::FileSystem`,
`AWS::KMS::Key` and `AWS::Backup::BackupVault` reject it outright. A single library-wide "safe removal
policies" union would be wrong for somebody, and wrong in the direction of emitting a template that
fails at deploy — hence `NonDestructiveRemovalPolicy` and `SnapshottableRemovalPolicy`.

Check what the resource actually accepts. Do not generalise from the last one.

## 3. A wrapper creates what its construct would have created anyway

- `ec2.Vpc` already creates a log group when flow logs are configured, so `Vpc` creates one.
- `lambda.Function` does **not**: Lambda makes `/aws/lambda/<name>` at first invocation, and that
  log group never appears in CloudFormation — never tagged, never encrypted, unbounded retention.
  So `Function` **requires** the caller to name one.

The rule: **create what the wrapped construct creates; require a name for anything that would
otherwise be invisible to the template.** Making a hidden resource explicit is the whole point;
inventing a new one breaks the drop-in promise.

## 4. Two tiers, and the second one is capped

- **`cmmc2/aws-*`** — 1:1 wrappers. Same constructor shape, same methods, same construct paths, so
  they can replace a plain CDK construct in an existing stack without CloudFormation replacing the
  resource.
- **`cmmc2/patterns`** — composites, and **only** where a control genuinely needs more than one
  resource. `EFSInBackupPlan` requires an `AWS::Backup::BackupSelection`; a 1:1 wrapper cannot
  create one without ceasing to be a drop-in replacement.

Patterns are not for convenience bundles. If a composite exists only to save typing, it does not
belong here.

**No app-specific utilities.** No `validateEcrImageTag`, no `generateRandomPassword`, no
`toPascalCase`. Those are application plumbing, not controls.

## 5. Override the method people will actually call

Hardening on a differently-named method is not hardening. `FargateTaskDefinition` once put its
container controls on `addComplianceContainer` and left the inherited `addContainer` accepting
`privileged: true` with a writable root and no logging — so the obvious name was the insecure one.

If a base-class method can produce a non-compliant result, override it.

## 6. Outstanding findings are pinned, never suppressed

Where a construct cannot satisfy a cdk-nag rule, the finding stays visible and a test asserts the
exact set. Never `NagSuppressions`, never a blanket ignore.

Pinning does two things: it forces a future rule addition to fail the build here rather than surface
in somebody's audit, and it keeps the evidence report honest about what is not covered.

Each outstanding finding needs a documented reason, and the reason has to be real:

- **Structural** — `IAMNoInlinePolicy` on the CDK-generated Lambda execution role.
- **Contextual** — `LambdaConcurrency`: reserved concurrency draws on a fixed account pool of 1000
  with 100 required unreserved, so setting it everywhere would break deployments at scale.
- **A genuine AWS constraint** — ELB cannot deliver access logs to a KMS-encrypted bucket, which is
  why `ServiceLogBucket` exists and is the one bucket here on SSE-S3.
- **A false positive** — the RDS rotation Lambda's ingress rule uses an unresolved `Fn::GetAtt` port
  that cdk-nag cannot prove is not 22.

"It was inconvenient" is not on that list. Turning credential rotation off would clear two RDS
findings; it is not on offer, because that trades a real control for a cosmetic one.

## 7. Claims state what they do **not** evidence

Every control claim carries a `caveat`, and no claim is `full`. Infrastructure configuration is
almost never the whole of a practice — key custody, restore testing, and review procedures live
outside the template.

Claims are authored inline at the construct implementing them, so a claim cannot drift from the code
backing it. A claim may also weaken with configuration: `Secret` reports `supporting` when no
rotation is attached and `partial` when one is, so the evidence report tells the truth about which
secrets are rotated without anyone maintaining a list.

The generated coverage report always shows the denominator — "16 of 110" — because a report that
lists only what you address cannot tell an assessor what you do not.

## 8. Cross-bundle identity uses `Symbol.for`, never `instanceof`

The package ships one bundle per subpath with code splitting off, so `cmmc2` and `cmmc2/patterns`
each carry their own copy of shared modules — and therefore their own classes and their own
module-level state. `CompliantStack.of` used `instanceof` and broke on the exact import combination
the README recommends. The CloudWatch Logs key grant deduplicated through a module-level `WeakMap`
and worked only because CDK happens to merge identical policy statements.

Anything that must be identical across subpaths goes through `Symbol.for`, or lives on the object
itself rather than in module scope.

## 9. Every published subpath must actually resolve

`cdk init app --language typescript` still generates a tsconfig using classic node10 resolution,
which ignores the `exports` map entirely. Each subpath therefore ships a stub directory at the
package root, and `scripts/gen-subpath-stubs.mjs` **fails the build** if one is missing from
`package.json` `files`.

`/verify` and `/report` shipped broken for exactly this reason. The guard exists so it cannot happen
twice.

## 10. Attack your own guarantees

Assertions that the code does what you designed will pass while the control is bypassable — every
high-severity bug found so far had the same shape: **the guarantee held for the case that was
thought of and was absent for the adjacent one.** `tcp(22)` but not `allTraffic()`.
`addComplianceContainer` but not `addContainer`. `cmmc2/*` stubs but not `verify/`.

New controls get an entry in [`tests/adversarial.spec.ts`](../tests/adversarial.spec.ts) that tries
to defeat them. Ask specifically: what is the *adjacent* input I have not considered?

## 11. The external gate outranks our own tests

> Every construct passes `NIST80053R5Checks` with zero suppressions, or its outstanding findings are
> pinned and explained.

Asserting our own synthesized properties proves we wrote what we meant to. Running someone else's
rule pack proves what we wrote is the accepted configuration. The second is worth more, and it has
repeatedly found gaps the first could not — RDS enhanced monitoring was missing precisely because
the hand-written probe set it and the wrapper did not.

The reference app in `scripts/build-coverage.mjs` runs against `dist/`, not `src/`, which is what
caught the cross-bundle `instanceof` bug that unit tests structurally could not see.

---

## What this library is not

It does not make you CMMC compliant, and no amount of construct design will. Level 2 is 110
practices, most of them organizational — policy, training, incident response, personnel screening.
This addresses the technically enforceable subset and generates a report saying exactly which
practices it touches, how completely, and what is still owed.

It also cannot stop a determined caller. `node.defaultChild` escape hatches, direct
`aws-cdk-lib` imports, and console clickops are all outside its reach — that is what the cdk-nag
layer at synth and AWS Config at runtime are for. The aim is that the compliant path is the
easy one and the non-compliant path takes deliberate effort, not that the latter is impossible.
