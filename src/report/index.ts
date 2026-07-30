import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { type IConstruct } from 'constructs'

import { buildAttestation, type Attestation, type BuildAttestationOptions } from './model.js'
import {
  renderCoverageMarkdown,
  renderEvidenceCsv,
  renderUntaggedCsv,
} from './render.js'

export {
  addressedPractices,
  buildAttestation,
  summarizeByDomain,
  type Attestation,
  type AttestationViolation,
  type BuildAttestationOptions,
  type DomainSummary,
  type PracticeCoverage,
} from './model.js'

export {
  README_MARKER_END,
  README_MARKER_START,
  injectCoverageTable,
  renderCoverageMarkdown,
  renderCoverageTable,
  renderEvidenceCsv,
  renderUntaggedCsv,
} from './render.js'

/** Files written by {@link writeAttestation}. */
export interface WrittenAttestation {
  readonly attestation: Attestation
  readonly files: readonly string[]
}

/**
 * Build an attestation from a construct tree and write the report set.
 *
 * Call this from a CDK app before `app.synth()`. The reports are derived from
 * the construct tree, which exists only in process - control claims are not
 * serialized into the cloud assembly, so there is nothing in `cdk.out` for a
 * standalone tool to read.
 *
 * `attestation.json` is written alongside the reports so the `attest` CLI can
 * re-render them in CI without re-synthesizing the app.
 */
export function writeAttestation(
  scope: IConstruct,
  outDir: string,
  options: BuildAttestationOptions = {}
): WrittenAttestation {
  const attestation = buildAttestation(scope, options)

  mkdirSync(outDir, { recursive: true })

  const files: [string, string][] = [
    ['attestation.json', `${JSON.stringify(attestation, null, 2)}\n`],
    ['coverage.md', renderCoverageMarkdown(attestation)],
    ['evidence.csv', renderEvidenceCsv(attestation)],
    ['untagged.csv', renderUntaggedCsv(attestation)],
  ]

  for (const [name, contents] of files) {
    writeFileSync(join(outDir, name), contents, 'utf8')
  }

  return { attestation, files: files.map(([name]) => join(outDir, name)) }
}
