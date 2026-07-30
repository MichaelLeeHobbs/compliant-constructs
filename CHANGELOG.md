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
