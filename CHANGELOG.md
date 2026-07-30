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

### Changed

- **Peer dependencies:** `aws-cdk-lib` floor raised to `^2.257.0`, and `cdk-nag` is now optional.
  cdk-nag v3 requires `aws-cdk-lib@^2.257.0`, so the previous `^2.165.0` floor combined with a
  required `cdk-nag@^3` peer was unsatisfiable - the two could not be installed together.
- `Cmmc2Practice` now carries `revision`, `domainAbbrev`, and `requirementKind`; `ControlClaim`
  gained an optional `frameworkRevision`. CMMC Level 2 is pinned to SP 800-171 Rev 2, and Rev 3
  rulemaking is underway, so claims must record which revision they were made against.
