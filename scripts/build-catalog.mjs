/**
 * Generate src/cmmc2/catalog.generated.ts from the vendored NIST source data.
 *
 * Run with `--check` to verify the committed catalog is current without
 * writing (used in CI, so drift is a red build rather than a silent lie).
 *
 * Why generated rather than hand-written: a compliance library's control
 * catalog is the one thing that must not be approximately right. Deriving it
 * from NIST's own published CSV, behind assertions that would fail on a bad
 * parse, removes the human transcription step entirely.
 */
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join(root, 'src/cmmc2/catalog.generated.ts')
const MANIFEST = join(root, 'data/MANIFEST.json')

/**
 * The 14 NIST SP 800-171 families, their CMMC domain abbreviations, and the
 * number of requirements each must contain.
 *
 * This is the only hand-authored mapping in the pipeline. The abbreviations
 * are inherited from SP 800-53 family codes, which is why four of them are not
 * the obvious initials: Physical Protection is PE, Security Assessment is CA,
 * and 3.13/3.14 are SC/SI. Those four are exactly where a hand-written catalog
 * goes wrong, so they are asserted rather than trusted.
 *
 * Counts are from SP 800-171 Rev 2 and sum to 110.
 */
const FAMILIES = [
  { num: 1, abbrev: 'AC', domain: 'Access Control', count: 22 },
  { num: 2, abbrev: 'AT', domain: 'Awareness and Training', count: 3 },
  { num: 3, abbrev: 'AU', domain: 'Audit and Accountability', count: 9 },
  { num: 4, abbrev: 'CM', domain: 'Configuration Management', count: 9 },
  { num: 5, abbrev: 'IA', domain: 'Identification and Authentication', count: 11 },
  { num: 6, abbrev: 'IR', domain: 'Incident Response', count: 3 },
  { num: 7, abbrev: 'MA', domain: 'Maintenance', count: 6 },
  { num: 8, abbrev: 'MP', domain: 'Media Protection', count: 9 },
  { num: 9, abbrev: 'PS', domain: 'Personnel Security', count: 2 },
  { num: 10, abbrev: 'PE', domain: 'Physical Protection', count: 6 },
  { num: 11, abbrev: 'RA', domain: 'Risk Assessment', count: 3 },
  { num: 12, abbrev: 'CA', domain: 'Security Assessment', count: 4 },
  { num: 13, abbrev: 'SC', domain: 'System and Communications Protection', count: 16 },
  { num: 14, abbrev: 'SI', domain: 'System and Information Integrity', count: 7 },
]

const EXPECTED_TOTAL = 110

/** Minimal RFC 4180 parser. The NIST CSV quotes fields containing newlines. */
function parseCsv(text) {
  const rows = []
  let row = []
  let field = ''
  let inQuotes = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (inQuotes) {
      if (c !== '"') {
        field += c
      } else if (text[i + 1] === '"') {
        field += '"'
        i++
      } else {
        inQuotes = false
      }
      continue
    }
    if (c === '"') inQuotes = true
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
  return rows.filter(r => r.some(cell => cell.trim() !== ''))
}

function fail(message) {
  throw new Error(`catalog invariant violated: ${message}`)
}

/** Parse the NIST CSV into requirement records, asserting the shape is intact. */
function readRequirements(manifest) {
  const source = manifest.files.find(f => f.id === 'sp800-171r2-security-reqs')
  if (!source) fail('MANIFEST.json has no sp800-171r2-security-reqs entry')

  const path = join(root, 'data', source.path)
  const bytes = readFileSync(path)

  // The vendored source is the root of trust for every claim this library
  // makes. If it changes, that must be a deliberate, reviewed act.
  const actual = createHash('sha256').update(bytes).digest('hex')
  if (actual !== source.sha256) {
    fail(`${source.path} sha256 is ${actual}, MANIFEST.json expects ${source.sha256}`)
  }

  // Strip the UTF-8 BOM; NIST ships one. Written as an escape rather than the
  // literal character so the source stays ASCII-only.
  const rows = parseCsv(bytes.toString('utf8').replace(/^\uFEFF/, ''))
  const header = rows[0].map(h => h.trim())
  const col = name => {
    const i = header.indexOf(name)
    // Note: NIST's header for the requirement text carries a leading space,
    // hence the trim above. If they ever fix it, this still works.
    if (i === -1) fail(`CSV is missing the "${name}" column (found: ${header.join(', ')})`)
    return i
  }

  const iFamily = col('Family')
  const iKind = col('Basic/Derived Security Requirement')
  const iId = col('Identifier')
  const iText = col('Security Requirement')

  return rows.slice(1).map(r => ({
    nistFamily: r[iFamily].trim(),
    kind: r[iKind].trim().toLowerCase(),
    id: r[iId].trim(),
    text: r[iText].trim(),
  }))
}

/** Apply every structural invariant, then derive the CMMC practice entries. */
function buildPractices(requirements) {
  if (requirements.length !== EXPECTED_TOTAL) {
    fail(`expected ${EXPECTED_TOTAL} requirements, parsed ${requirements.length}`)
  }
  if (new Set(requirements.map(r => r.id)).size !== requirements.length) {
    fail('duplicate requirement identifiers')
  }

  const practices = []

  for (const family of FAMILIES) {
    const prefix = `3.${family.num}.`
    const members = requirements.filter(r => r.id.startsWith(prefix))

    if (members.length !== family.count) {
      fail(
        `family 3.${family.num} (${family.domain}) has ${members.length} requirements, expected ${family.count}`
      )
    }

    // NIST's own family label must agree with ours, case-insensitively -
    // the CSV writes "Incident response" with a lowercase r.
    for (const m of members) {
      if (m.nistFamily.toLowerCase() !== family.domain.toLowerCase()) {
        fail(
          `${m.id} is labelled "${m.nistFamily}" but 3.${family.num} should be "${family.domain}"`
        )
      }
      if (m.text === '') fail(`${m.id} has empty requirement text`)
      if (m.kind !== 'basic' && m.kind !== 'derived') fail(`${m.id} has unknown kind "${m.kind}"`)
    }

    // Contiguity is what catches a dropped or misparsed row: a family must run
    // 1..n with no gaps.
    const ordinals = members.map(m => Number(m.id.slice(prefix.length))).sort((a, b) => a - b)
    ordinals.forEach((n, i) => {
      if (n !== i + 1) fail(`family 3.${family.num} is not contiguous: expected ${i + 1}, got ${n}`)
    })

    for (const n of ordinals) {
      const req = members.find(m => m.id === `${prefix}${n}`)
      const id = `${family.abbrev}.L2-${req.id}`
      if (!/^[A-Z]{2}\.L2-3\.\d{1,2}\.\d{1,2}$/.test(id))
        fail(`derived practice id "${id}" is malformed`)
      if (!id.endsWith(req.id))
        fail(`practice id "${id}" does not end with requirement "${req.id}"`)

      practices.push({
        id,
        domain: family.domain,
        domainAbbrev: family.abbrev,
        title: req.text,
        nist800171: req.id,
        requirementKind: req.kind,
      })
    }
  }

  if (practices.length !== EXPECTED_TOTAL) {
    fail(`derived ${practices.length} practices, expected ${EXPECTED_TOTAL}`)
  }
  return practices
}

const q = s => `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`

function render(practices, manifest) {
  const source = manifest.files.find(f => f.id === 'sp800-171r2-security-reqs')

  const entries = practices
    .map(
      p => `  ${q(p.id)}: {
    id: ${q(p.id)},
    domain: ${q(p.domain)},
    domainAbbrev: ${q(p.domainAbbrev)},
    level: 2,
    revision: 'rev2',
    requirementKind: ${q(p.requirementKind)},
    nist800171: ${q(p.nist800171)},
    title: ${q(p.title)},
  },`
    )
    .join('\n')

  return `// GENERATED FILE - DO NOT EDIT.
// Run \`pnpm run catalog:build\` to regenerate. CI fails if this file is stale.
//
// Derived from ${source.title}
//   ${source.url}
//   retrieved ${source.retrieved}, sha256 ${source.sha256}
//   ${source.license}
//
// CMMC 2.0 Level 2 practices correspond 1:1 to the ${EXPECTED_TOTAL} security
// requirements of NIST SP 800-171 Rev 2. Practice IDs are derived as
// <DOMAIN>.L2-<requirement>, with the domain abbreviation taken from the
// SP 800-53 family code for that family.

/** How completely a requirement is stated in SP 800-171: a base requirement or one derived from it. */
export type Cmmc2RequirementKind = 'basic' | 'derived'

/** The revision of NIST SP 800-171 a practice is defined against. */
export type Cmmc2Revision = 'rev2'

/** CMMC 2.0 Level 2 practice identifiers. All ${EXPECTED_TOTAL} of them. */
export type Cmmc2PracticeId =
${practices.map(p => `  | ${q(p.id)}`).join('\n')}

/** A single CMMC 2.0 Level 2 practice and its NIST SP 800-171 origin. */
export interface Cmmc2Practice {
  readonly id: Cmmc2PracticeId
  /** Capability domain, e.g. 'System and Communications Protection'. */
  readonly domain: string
  /** Two-letter domain code, e.g. 'SC'. */
  readonly domainAbbrev: string
  /** CMMC level at which the practice is assessed. */
  readonly level: 2
  /** SP 800-171 revision this text is taken from. CMMC Level 2 is pinned to rev2. */
  readonly revision: Cmmc2Revision
  readonly requirementKind: Cmmc2RequirementKind
  /** Corresponding SP 800-171 requirement number, e.g. '3.13.16'. */
  readonly nist800171: string
  /** Requirement text, verbatim from NIST. */
  readonly title: string
}

/** Every CMMC 2.0 Level 2 practice, keyed by identifier. */
export const CMMC2_PRACTICES: Readonly<Record<Cmmc2PracticeId, Cmmc2Practice>> = {
${entries}
}

/** Total number of CMMC 2.0 Level 2 practices. The denominator for coverage reporting. */
export const CMMC2_PRACTICE_COUNT = ${EXPECTED_TOTAL}
`
}

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'))
const output = render(buildPractices(readRequirements(manifest)), manifest)

if (process.argv.includes('--check')) {
  const current = readFileSync(OUT, 'utf8')
  if (current !== output) {
    console.error(
      'catalog is stale: src/cmmc2/catalog.generated.ts does not match the vendored source data.\n' +
        'Run `pnpm run catalog:build` and commit the result.'
    )
    process.exit(1)
  }
  console.warn(`catalog is current (${EXPECTED_TOTAL} practices)`)
} else {
  writeFileSync(OUT, output, 'utf8')
  console.warn(`wrote src/cmmc2/catalog.generated.ts (${EXPECTED_TOTAL} practices)`)
}
