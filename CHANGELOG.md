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

### Changed

- `Cmmc2Practice` now carries `revision`, `domainAbbrev`, and `requirementKind`; `ControlClaim`
  gained an optional `frameworkRevision`. CMMC Level 2 is pinned to SP 800-171 Rev 2, and Rev 3
  rulemaking is underway, so claims must record which revision they were made against.
