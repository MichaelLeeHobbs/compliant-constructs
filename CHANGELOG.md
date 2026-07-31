# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffold: pnpm, tsup dual ESM/CJS build, jest, eslint flat config, prettier, CI and
  tag-triggered publish workflows.
- `ControlClaim` metadata primitives (`addControlClaims`, `collectControlClaims`) - the foundation
  the evidence report is generated from.
- CMMC 2.0 practice catalog (`CMMC2_PRACTICES`) with NIST SP 800-171 Rev 2 mappings, and the typed
  `cmmc2Claim()` helper.
- Subpath export machinery, including generated stub directories so classic node10 module
  resolution (still the `cdk init` default) can resolve subpaths.
- All 110 CMMC 2.0 Level 2 practices, generated from NIST's own published SP 800-171 Rev 2
  requirements CSV rather than transcribed by hand. The vendored source is checksummed, the
  generator enforces nine structural invariants, and `catalog:check` fails CI if the committed
  catalog drifts from the source data.
- `data/MANIFEST.json` recording provenance (origin URL, retrieval date, sha256, license) for every
  vendored data file.

- `cmmc2/aws-efs` - `FileSystem`, a drop-in replacement for `efs.FileSystem` that mandates
  encryption with a customer-managed key, automatic backups, a TLS-only resource policy, and a
  non-destructive removal policy, and rejects mount targets in public subnets. Creates exactly the
  resources the construct it wraps creates, so it can replace one without changing construct paths.
- `cmmc2/patterns` - `EncryptedFileSystem`, composing a rotating CMK, a default-deny security group,
  and enrolment in an AWS Backup plan writing to an encrypted vault. Passes `NIST80053R5Checks` with
  zero suppressions.
- `CompliantStack`, taking typed required tags in place of `StackProps.tags`.
- `findUntaggableResources()`, listing resources that cannot carry CDK tags rather than letting them
  fall silently out of an assessment scope boundary.
- `/verify` subpath with `verifyCompliance()` and `parseNagControlIds()`.
- Compile-time negative tests (`tests/types.compile.ts`) asserting that non-compliant
  configurations do not typecheck.

- `/report` subpath: `buildAttestation()`, `writeAttestation()` and renderers producing
  `coverage.md`, `evidence.csv`, `untagged.csv` and `attestation.json` from control-claim metadata.
- `attest` CLI, rendering those reports from a committed attestation and injecting a coverage table
  between markers in a README. `--check` fails CI when committed reports are stale.
- Generated coverage documentation for this library: `docs/coverage.md` and the README coverage
  table, both produced by `pnpm run coverage:build` and verified by `pnpm run coverage:check`.

- `cmmc2/aws-s3` - `Bucket`, mandating KMS customer-managed encryption, full public-access
  blocking, TLS-only access, versioning, `BucketOwnerEnforced` ownership and server access logging.
- `cmmc2/aws-rds` - `DatabaseInstance`, mandating storage encryption with a customer-managed key, a
  CMK-encrypted generated credential secret on a rotation schedule, IAM authentication, deletion
  protection, enhanced monitoring, Performance Insights, and engine log exports.
- `cmmc2/patterns` - `SecureBucket` and `EncryptedDatabaseInstance`.
- `SnapshottableRemovalPolicy`, alongside `NonDestructiveRemovalPolicy`. RDS accepts a `Snapshot`
  deletion policy where S3, EFS, KMS and Backup vaults do not, so the narrowing differs per resource.

- `CompliantStack` now supplies a stack-scoped customer-managed key, created lazily on first use,
  with `CompliantStack.of()` and `resolveEncryptionKey()` for constructs to reach it.

- `cmmc2/aws-kms` - `Key`, mandating annual rotation and a non-destructive removal policy.
- `cmmc2/aws-logs` - `LogGroup`, mandating a customer-managed key and an explicit retention
  period. Adds the CloudWatch Logs service statement to the key policy when it attaches, scoped by
  an encryption-context condition, and only once per key per region.
- `cmmc2/aws-secretsmanager` - `Secret`, mandating a customer-managed key, with optional hosted
  rotation. The claim it records weakens when no rotation is configured.
- `cmmc2/aws-ec2` - `SecurityGroup`, closed in both address families by default, requiring a
  description, and refusing SSH or RDP ingress from `0.0.0.0/0` or `::/0`.

- `cmmc2/aws-sqs` - `Queue`, mandating KMS customer-managed encryption and a TLS-only queue policy.
- `cmmc2/aws-sns` - `Topic`, mandating KMS customer-managed encryption and TLS-only publishing.
- `cmmc2/aws-dynamodb` - `Table`, mandating a customer-managed key and point-in-time recovery.
  PITR is required even though the R5 pack does not check for it: a table is often the only copy
  of what it holds.
- `cmmc2/aws-lambda` - `Function`, requiring an explicit log group so the one Lambda creates for
  itself - never in the template, never tagged, never encrypted, unbounded retention - stops being
  invisible. Encrypts environment variables and enables tracing.
- `cmmc2/patterns` - `SecureFunction`, creating that log group plus a dead-letter queue.

- `cmmc2/aws-cloudtrail` - `Trail`, mandating multi-region coverage, global service events,
  log file validation, KMS encryption and CloudWatch delivery, with both destinations named
  rather than conjured.
- `cmmc2/aws-elasticloadbalancingv2` - `ApplicationLoadBalancer`, requiring an access log
  bucket and mandating deletion protection and invalid-header dropping.
- `cmmc2/patterns` - `ServiceLogBucket`, an SSE-S3 destination for AWS service log delivery.
  It is the one bucket here without a customer-managed key, because ELB cannot deliver access
  logs to a KMS-encrypted bucket at all.

- `cmmc2/aws-ec2` - `Vpc`, always flow-logged to an encrypted log group, with the default
  security group stripped and public subnets no longer auto-assigning public IPs.
- `cmmc2/aws-ecs` - `Cluster`, `FargateTaskDefinition` and `FargateService`. Containers added
  via `addComplianceContainer()` run with a read-only root filesystem, cannot be privileged, and
  must have a log driver; services never receive a public IP.

- `docs/design-principles.md`, stating the goal - a non-compliant resource should be hard to
  express - and the eleven rules the constructs follow, from how to rank a mandate through to
  pinning outstanding findings and attacking your own guarantees.

- `cmmc2/aws-securityhub` - `Hub`, enabling Security Hub with NIST 800-53 Rev 5 always on, plus
  AWS Foundational and CIS v3 by default. Standard ARNs resolve per partition.
- `cmmc2/aws-guardduty` - `Detector`, enabled, with the six-hour publishing frequency removed
  from the type.
- `cmmc2/aws-config` - `ConfigurationRecorder`, recording every supported resource type including
  global ones, with the bucket policy AWS Config needs in order to deliver at all.
- `cmmc2/patterns` - `AccountBaseline`, composing CloudTrail, Config, Security Hub and GuardDuty.
  This is what moves the CA and RA domains off zero: no amount of correct resource configuration
  answers whether security controls are monitored on an ongoing basis.

- `verifyArchitecture()` - checks over the assembled construct graph, for the properties a
  per-resource rule engine cannot see. A VPC with no endpoints and open egress passes the whole
  NIST 800-53 R5 pack; these four checks are what notice.
- `cmmc2/patterns` - `CuiVpc`, isolated subnets with no internet or NAT gateway, VPC endpoints
  with private DNS, and network ACLs permitting VPC-internal traffic only. FIPS endpoint variants
  are selected by default.
- `cmmc2/patterns` - `SessionManagerAccess`, administrative access with no bastion and no inbound
  port, session transcripts to an encrypted log group, and an idle timeout.
- `cmmc2/patterns` - `EbsEncryptionByDefault`, an account-wide setting so volumes created outside
  CloudFormation are encrypted too.
- `cmmc2/aws-ec2` - `InterfaceVpcEndpoint`, mandating private DNS and its own narrow security
  group.
- `cmmc2/aws-certificatemanager` - `Certificate`, DNS-validated so ACM can renew it unattended.
- `cmmc2/aws-wafv2` - `WebAcl`, managed rule groups in block mode rather than count.
- `addHttpsListener()` and `addHttpsRedirect()` on the load balancer module, with TLS 1.3/1.2
  policies only.

### Fixed

- **`SecurityGroup` let `Port.allTraffic()` through from `0.0.0.0/0`.** That port shape emits
  ipProtocol `-1` with no port range, and the guard read `fromPort` first and returned early -
  so the broadest and most dangerous rule of all was the one rule it did not block. It also no
  longer blocks `udp/22`, which was a false positive.
- **`FargateTaskDefinition.addContainer()` bypassed every container control.** Hardening lived
  on a separate `addComplianceContainer`, leaving the inherited method accepting
  `privileged: true` with a writable root and no logging. The hardening now overrides
  `addContainer`; `addComplianceContainer` is removed.
- **`/verify` and `/report` did not resolve for consumers.** Their stub directories were not
  in package.json `files`, so on TypeScript 5.x with the tsconfig `cdk init` generates, both
  subpaths failed - including the one the README example imports. The stub generator now fails
  the build if any subpath is missing from `files`.
- The CloudWatch Logs key-policy grant deduplicated through module-level state, which is
  per-bundle. It now records regions on the key itself via `Symbol.for`, so the dedupe holds
  across subpath bundles instead of relying on CDK merging identical statements.
- Evidence CSV cells beginning with `=`, `+`, `-` or `@` are prefixed so a spreadsheet treats
  them as text. Construct paths are caller-controlled and the file exists to be opened in Excel.
- `ServiceLogBucket` documented one outstanding finding; it has three. All are now named and
  pinned.

### Changed

- **Encryption keys are now stack-scoped by default.** `kmsKey` / `encryptionKey` became optional on
  every construct, resolving to the stack's key when omitted. A customer-managed key is still always
  used; what changed is whether the caller has to restate it. Using a construct outside a
  `CompliantStack` without an explicit key throws.
- Patterns no longer mint a key each. They default to the stack key, so a stack with three patterns
  has one key rather than three.
- `BucketReference` accepts either `s3.IBucket` or `s3.Bucket`, absorbing an aws-cdk-lib typing
  inconsistency (`isWebsite` is optional on the class, required on the interface) that otherwise
  forces a cast on every caller compiling with `exactOptionalPropertyTypes`.

### Fixed

- `CompliantStack.of()` used `instanceof`, which fails across bundle boundaries: with code splitting
  off, each published subpath carries its own copy of the class, so a stack from `cmmc2` was not
  `instanceof` the class inside `cmmc2/patterns`. That broke the exact import combination the README
  recommends. Now uses a `Symbol.for` marker, the same approach the CDK uses for `isConstruct`.

- **Peer dependencies:** `aws-cdk-lib` floor raised to `^2.257.0`, and `cdk-nag` is now optional.
  cdk-nag v3 requires `aws-cdk-lib@^2.257.0`, so the previous `^2.165.0` floor combined with a
  required `cdk-nag@^3` peer was unsatisfiable - the two could not be installed together.
- `Cmmc2Practice` now carries `revision`, `domainAbbrev`, and `requirementKind`; `ControlClaim`
  gained an optional `frameworkRevision`. CMMC Level 2 is pinned to SP 800-171 Rev 2, and Rev 3
  rulemaking is underway, so claims must record which revision they were made against.
