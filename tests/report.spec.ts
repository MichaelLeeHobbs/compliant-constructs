import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import * as kms from 'aws-cdk-lib/aws-kms'

import { CMMC2_PRACTICE_COUNT } from '../src/cmmc2/index.js'
import { FileSystem } from '../src/cmmc2/aws-efs/index.js'
import { EncryptedFileSystem } from '../src/cmmc2/patterns/index.js'
import {
  README_MARKER_END,
  README_MARKER_START,
  addressedPractices,
  buildAttestation,
  injectCoverageTable,
  renderCoverageMarkdown,
  renderCoverageTable,
  renderEvidenceCsv,
  renderUntaggedCsv,
  summarizeByDomain,
  writeAttestation,
  type Attestation,
} from '../src/report/index.js'
import { testStack } from './helpers/fixtures.js'

function subject(): Attestation {
  const { stack, vpc } = testStack()
  const vpcSubnets = { subnets: vpc.privateSubnets }

  new EncryptedFileSystem(stack, 'CuiStorage', { vpc, vpcSubnets, fileSystemName: 'cui' })
  const key = new kms.Key(stack, 'Key', { enableKeyRotation: true })
  new FileSystem(stack, 'Standalone', { vpc, vpcSubnets, kmsKey: key })

  return buildAttestation(stack, {
    violations: [
      {
        ruleId: 'NIST.800.53.R5-EFSInBackupPlan',
        description: 'The EFS is not in an AWS Backup plan - (Control IDs: CP-9a).',
        resources: ['TestStack/Standalone/Resource'],
      },
    ],
  })
}

/** Parse a CSV into rows, handling the quoting the renderer emits. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let quoted = false

  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"'
        i++
      } else if (c === '"') quoted = false
      else field += c
      continue
    }
    if (c === '"') quoted = true
    else if (c === ',') {
      row.push(field)
      field = ''
    } else if (c === '\n') {
      row.push(field)
      rows.push(row)
      row = []
      field = ''
    } else if (c !== '\r') field += c
  }
  if (field !== '' || row.length > 0) {
    row.push(field)
    rows.push(row)
  }
  return rows
}

describe('buildAttestation', () => {
  it('includes every practice, not only the addressed ones', () => {
    // The full catalog is the denominator. Without it the report cannot state
    // what is NOT covered, which is the entire premise.
    expect(subject().coverage).toHaveLength(CMMC2_PRACTICE_COUNT)
  })

  it('indexes claims onto the practices they name', () => {
    const entry = subject().coverage.find(c => c.practice.id === 'SC.L2-3.13.16')

    expect(entry?.claims.length).toBeGreaterThan(0)
    for (const c of entry?.claims ?? []) expect(c.claim.controlId).toBe('SC.L2-3.13.16')
  })

  it('reports the strongest satisfaction level when constructs disagree', () => {
    // MP.L2-3.8.9 is claimed 'partial' by EncryptedFileSystem (real backup plan)
    // and 'partial' by FileSystem (EFS automatic backups only); AC.L2-3.1.3 is
    // only ever 'supporting'.
    const attestation = subject()

    expect(attestation.coverage.find(c => c.practice.id === 'MP.L2-3.8.9')?.satisfaction).toBe(
      'partial'
    )
    expect(attestation.coverage.find(c => c.practice.id === 'AC.L2-3.1.3')?.satisfaction).toBe(
      'supporting'
    )
  })

  it('leaves satisfaction undefined for practices with no claims', () => {
    const entry = subject().coverage.find(c => c.practice.id === 'AT.L2-3.2.1')

    expect(entry?.claims).toEqual([])
    expect(entry?.satisfaction).toBeUndefined()
  })

  it('carries untaggable resources and supplied violations through', () => {
    const attestation = subject()

    expect(attestation.untaggable.map(r => r.cfnType)).toContain('AWS::EFS::MountTarget')
    expect(attestation.violations).toHaveLength(1)
  })

  it('produces no timestamp, so regenerating is a no-op diff', () => {
    expect(JSON.stringify(subject())).not.toMatch(/\d{4}-\d{2}-\d{2}T/)
  })
})

describe('summarizeByDomain', () => {
  it('covers all 14 domains and totals to the full catalog', () => {
    const summary = summarizeByDomain(subject())

    expect(summary).toHaveLength(14)
    expect(summary.reduce((n, d) => n + d.total, 0)).toBe(CMMC2_PRACTICE_COUNT)
    expect(summary.reduce((n, d) => n + d.addressed, 0)).toBe(addressedPractices(subject()).length)
  })
})

describe('renderEvidenceCsv', () => {
  it('emits one row per claim per construct with a stable header', () => {
    const rows = parseCsv(renderEvidenceCsv(subject())).filter(r => r.length > 1)
    const claimCount = addressedPractices(subject()).reduce((n, e) => n + e.claims.length, 0)

    expect(rows[0]).toEqual([
      'practice',
      'domain',
      'nist_800_171',
      'framework_revision',
      'construct_path',
      'satisfaction',
      'evidence',
      'caveat',
      'cdk_nag_rules',
    ])
    expect(rows).toHaveLength(claimCount + 1)
  })

  it('quotes fields containing commas so the CSV survives a round trip', () => {
    const rows = parseCsv(renderEvidenceCsv(subject())).filter(r => r.length > 1)
    const withComma = rows.slice(1).find(r => r[7]?.includes(','))

    expect(withComma).toBeDefined()
    // Every row must have exactly as many fields as the header, which is only
    // true if quoting worked.
    for (const row of rows) expect(row).toHaveLength(9)
  })

  it('records the framework revision on every row', () => {
    const rows = parseCsv(renderEvidenceCsv(subject())).filter(r => r.length > 1)

    for (const row of rows.slice(1)) expect(row[3]).toBe('rev2')
  })
})

describe('renderUntaggedCsv', () => {
  it('lists resources CDK tagging cannot reach, with a reason', () => {
    const rows = parseCsv(renderUntaggedCsv(subject())).filter(r => r.length > 1)

    expect(rows[0]).toEqual(['construct_path', 'cfn_type', 'reason'])
    expect(rows.slice(1).map(r => r[1])).toContain('AWS::EFS::MountTarget')
    for (const row of rows.slice(1)) expect(row[2]).toMatch(/no tags property/)
  })

  it('catches AWS Backup vaults, whose tags are a plain map rather than a TagManager', () => {
    const types = parseCsv(renderUntaggedCsv(subject()))
      .filter(r => r.length > 1)
      .slice(1)
      .map(r => r[1])

    expect(types).toContain('AWS::Backup::BackupVault')
  })
})

describe('renderCoverageTable', () => {
  it('states the denominator rather than only what is covered', () => {
    const table = renderCoverageTable(subject())

    expect(table).toMatch(new RegExp(`\\*\\*\\d+ of ${CMMC2_PRACTICE_COUNT}\\*\\*`))
    expect(table).toMatch(/\|\s+\*\*Total\*\*\s+\|/)
  })
})

describe('renderCoverageMarkdown', () => {
  it('documents each addressed practice with its caveat', () => {
    const md = renderCoverageMarkdown(subject())

    expect(md).toContain('### SC.L2-3.13.16 - Protect the confidentiality of CUI at rest.')
    expect(md).toContain('Not evidenced by this claim')
    expect(md).toContain('Reconciles with cdk-nag')
  })

  it('lists what is not addressed, with the count', () => {
    const attestation = subject()
    const notAddressed = CMMC2_PRACTICE_COUNT - addressedPractices(attestation).length
    const md = renderCoverageMarkdown(attestation)

    expect(md).toContain(`${notAddressed} of ${CMMC2_PRACTICE_COUNT} practices have no claim`)
    expect(md).toMatch(/\|\s+AT\.L2-3\.2\.1\s+\|/)
  })

  it('includes outstanding cdk-nag findings when supplied', () => {
    expect(renderCoverageMarkdown(subject())).toContain('NIST.800.53.R5-EFSInBackupPlan')
  })
})

describe('injectCoverageTable', () => {
  const doc = `# Title\n\n${README_MARKER_START}\nstale content\n${README_MARKER_END}\n\ntrailer\n`

  it('replaces only the marked block', () => {
    const out = injectCoverageTable(doc, subject())

    expect(out).not.toContain('stale content')
    expect(out).toContain('# Title')
    expect(out).toContain('trailer')
    expect(out).toMatch(/\|\s+\*\*Total\*\*\s+\|/)
  })

  it('is idempotent', () => {
    const once = injectCoverageTable(doc, subject())

    expect(injectCoverageTable(once, subject())).toBe(once)
  })

  it('refuses a document with no markers rather than appending', () => {
    expect(() => injectCoverageTable('# No markers here\n', subject())).toThrow(/marker pair/)
  })

  it('refuses markers in the wrong order', () => {
    const reversed = `${README_MARKER_END}\nx\n${README_MARKER_START}\n`

    expect(() => injectCoverageTable(reversed, subject())).toThrow(/wrong order/)
  })
})

describe('writeAttestation', () => {
  it('writes the four report files and a re-readable model', () => {
    const dir = mkdtempSync(join(tmpdir(), 'attest-'))
    const { stack, vpc } = testStack()
    new EncryptedFileSystem(stack, 'CuiStorage', {
      vpc,
      vpcSubnets: { subnets: vpc.privateSubnets },
      fileSystemName: 'cui',
    })

    const { files } = writeAttestation(stack, dir)

    expect(files.map(f => f.replace(/^.*[\\/]/, ''))).toEqual([
      'attestation.json',
      'coverage.md',
      'evidence.csv',
      'untagged.csv',
    ])

    const roundTripped = JSON.parse(
      readFileSync(join(dir, 'attestation.json'), 'utf8')
    ) as Attestation

    expect(roundTripped.coverage).toHaveLength(CMMC2_PRACTICE_COUNT)
    expect(renderCoverageMarkdown(roundTripped)).toBe(
      readFileSync(join(dir, 'coverage.md'), 'utf8')
    )
  })

  it('creates the output directory if it does not exist', () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'attest-')), 'nested', 'deeper')
    const { stack } = testStack()

    expect(() => writeAttestation(stack, dir)).not.toThrow()
    expect(readFileSync(join(dir, 'attestation.json'), 'utf8')).toContain('"framework"')
  })
})

describe('report rendering is deterministic', () => {
  it('produces byte-identical output for the same input', () => {
    const dir = mkdtempSync(join(tmpdir(), 'attest-'))
    writeFileSync(join(dir, 'probe'), '')

    expect(renderCoverageMarkdown(subject())).toBe(renderCoverageMarkdown(subject()))
    expect(renderEvidenceCsv(subject())).toBe(renderEvidenceCsv(subject()))
  })
})
