import {
  addressedPractices,
  summarizeByDomain,
  type Attestation,
  type PracticeCoverage,
} from './model.js'

/** Marker pair delimiting the generated block in a README or other document. */
export const README_MARKER_START = '<!-- compliant-constructs:coverage:start -->'
export const README_MARKER_END = '<!-- compliant-constructs:coverage:end -->'

/** RFC 4180 field escaping. */
function csvField(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value
}

function csvRow(fields: readonly string[]): string {
  return fields.map(csvField).join(',')
}

/** Escape a value for use inside a markdown table cell. */
function mdCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}

/** Wrap a value in backticks for a table cell. */
function mdCode(value: string): string {
  return `\`${mdCell(value)}\``
}

/**
 * Render a markdown table with columns padded to their widest cell.
 *
 * This matches how Prettier formats markdown tables, deliberately. These
 * documents get injected into READMEs, and a README that is Prettier-formatted
 * would otherwise be rewritten on every format run and reported as stale on
 * every `--check` - an unwinnable fight between two generators. Emitting the
 * canonical form up front means both agree.
 */
function mdTable(headers: readonly string[], rows: readonly (readonly string[])[]): string[] {
  const widths = headers.map((header, i) =>
    Math.max(header.length, ...rows.map(row => (row[i] ?? '').length))
  )

  const line = (cells: readonly string[]): string =>
    `| ${cells.map((cell, i) => cell.padEnd(widths[i] ?? cell.length)).join(' | ')} |`

  return [line(headers), `| ${widths.map(w => '-'.repeat(w)).join(' | ')} |`, ...rows.map(line)]
}

/**
 * Every claim, one row per claim per construct.
 *
 * This is the artifact an assessor works from: it ties a practice to a specific
 * construct path and states what about that resource constitutes the evidence.
 */
export function renderEvidenceCsv(attestation: Attestation): string {
  const rows = [
    csvRow([
      'practice',
      'domain',
      'nist_800_171',
      'framework_revision',
      'construct_path',
      'satisfaction',
      'evidence',
      'caveat',
      'cdk_nag_rules',
    ]),
  ]

  for (const entry of addressedPractices(attestation)) {
    for (const { path, claim } of entry.claims) {
      rows.push(
        csvRow([
          entry.practice.id,
          entry.practice.domain,
          entry.practice.nist800171,
          claim.frameworkRevision ?? attestation.revision,
          path,
          claim.satisfaction,
          claim.evidence,
          claim.caveat ?? '',
          (claim.nagRuleIds ?? []).join(' '),
        ])
      )
    }
  }

  return `${rows.join('\n')}\n`
}

/**
 * Resources that could not receive the required tags.
 *
 * Present so that a resource missing from a scope boundary because nothing
 * could tag it is distinguishable from one that was never in scope.
 */
export function renderUntaggedCsv(attestation: Attestation): string {
  const rows = [csvRow(['construct_path', 'cfn_type', 'reason'])]

  for (const resource of attestation.untaggable) {
    rows.push(
      csvRow([
        resource.path,
        resource.cfnType,
        'CloudFormation resource type has no tags property; CDK tagging cannot reach it',
      ])
    )
  }

  return `${rows.join('\n')}\n`
}

function satisfactionLabel(entry: PracticeCoverage): string {
  return entry.satisfaction ?? 'not addressed'
}

/**
 * Compact per-domain summary, suitable for embedding in a README.
 *
 * Deliberately reports the denominator. "9 of 110" is the honest headline;
 * "9 practices addressed" is the dishonest one.
 */
export function renderCoverageTable(attestation: Attestation): string {
  const summary = summarizeByDomain(attestation)
  const totalAddressed = summary.reduce((n, d) => n + d.addressed, 0)
  const total = summary.reduce((n, d) => n + d.total, 0)

  return [
    `**${totalAddressed} of ${total}** CMMC 2.0 Level 2 practices are addressed in part by this ` +
      'library. None are satisfied outright - see [`docs/coverage.md`](docs/coverage.md) for what ' +
      'each claim does and does not evidence.',
    '',
    ...mdTable(
      ['Domain', 'Addressed', 'Total'],
      [
        ...summary.map(d => [
          `${d.domainAbbrev} - ${mdCell(d.domain)}`,
          String(d.addressed),
          String(d.total),
        ]),
        ['**Total**', `**${totalAddressed}**`, `**${total}**`],
      ]
    ),
  ].join('\n')
}

/** The full practice-by-practice coverage document. */
// Long by design: this is a document template, and splitting it into helpers
// that each emit three lines would make the shape of the output harder to see.
// eslint-disable-next-line max-lines-per-function
export function renderCoverageMarkdown(attestation: Attestation): string {
  const addressed = addressedPractices(attestation)
  const notAddressed = attestation.coverage.filter(c => c.claims.length === 0)

  const out: string[] = [
    '# CMMC 2.0 Level 2 coverage',
    '',
    '> Generated by `pnpm run coverage:build`. Do not edit by hand.',
    '',
    'Practice text is taken verbatim from NIST SP 800-171 Rev 2, the revision CMMC Level 2 is',
    'pinned to by 32 CFR Part 170. Every claim below states what it evidences **and what it does',
    'not** - no practice here is satisfied by infrastructure configuration alone.',
    '',
    renderCoverageTable(attestation),
    '',
    '## Addressed practices',
    '',
  ]

  for (const entry of addressed) {
    out.push(`### ${entry.practice.id} - ${mdCell(entry.practice.title)}`)
    out.push('')
    out.push(
      `**Domain:** ${entry.practice.domain} · ` +
        `**NIST SP 800-171 Rev 2:** ${entry.practice.nist800171} · ` +
        `**Strongest claim:** ${satisfactionLabel(entry)}`
    )
    out.push('')
    out.push(
      ...mdTable(
        ['Construct', 'Level', 'Evidence', 'Not evidenced by this claim'],
        entry.claims.map(({ path, claim }) => [
          mdCode(path),
          claim.satisfaction,
          mdCell(claim.evidence),
          mdCell(claim.caveat ?? '-'),
        ])
      )
    )
    out.push('')

    const rules = [...new Set(entry.claims.flatMap(c => c.claim.nagRuleIds ?? []))]
    if (rules.length > 0) {
      out.push(`Reconciles with cdk-nag: ${rules.map(r => `\`${r}\``).join(', ')}`)
      out.push('')
    }
  }

  out.push('## Not addressed')
  out.push('')
  out.push(
    `${notAddressed.length} of ${attestation.coverage.length} practices have no claim against them.`,
    'Most are organizational rather than technical - policy, training, personnel screening - and',
    'are not the sort of thing infrastructure code can evidence. Some are simply not covered yet.',
    ''
  )
  out.push(
    ...mdTable(
      ['Practice', 'Requirement'],
      notAddressed.map(entry => [entry.practice.id, mdCell(entry.practice.title)])
    )
  )
  out.push('')

  if (attestation.untaggable.length > 0) {
    out.push('## Resources that cannot carry tags')
    out.push('')
    out.push(
      'CDK tagging reaches only CloudFormation resources whose type has a tags property. These',
      'are in the deployment but cannot carry the `ContainsCui` tag, so their scope is inherited',
      'from their parent rather than stated on the resource.',
      ''
    )
    out.push(
      ...mdTable(
        ['Construct', 'Type'],
        attestation.untaggable.map(r => [mdCode(r.path), r.cfnType])
      )
    )
    out.push('')
  }

  if (attestation.violations.length > 0) {
    out.push('## Outstanding cdk-nag findings')
    out.push('')
    out.push(
      ...mdTable(
        ['Rule', 'Resources'],
        attestation.violations.map(v => [
          mdCode(v.ruleId),
          v.resources.map(r => mdCode(r)).join(', '),
        ])
      )
    )
    out.push('')
  }

  return out.join('\n')
}

/**
 * Replace the generated block in a document, leaving everything else untouched.
 *
 * Throws rather than appending if the markers are absent: silently adding a
 * table to the bottom of someone's README is worse than saying nothing.
 */
export function injectCoverageTable(document: string, attestation: Attestation): string {
  const start = document.indexOf(README_MARKER_START)
  const end = document.indexOf(README_MARKER_END)

  if (start === -1 || end === -1) {
    throw new Error(
      `document does not contain the marker pair ${README_MARKER_START} ... ${README_MARKER_END}`
    )
  }
  if (end < start) {
    throw new Error('coverage markers are in the wrong order')
  }

  const before = document.slice(0, start + README_MARKER_START.length)
  const after = document.slice(end)

  return `${before}\n\n${renderCoverageTable(attestation)}\n\n${after}`
}
