import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { type Attestation } from '../report/model.js'
import {
  injectCoverageTable,
  renderCoverageMarkdown,
  renderEvidenceCsv,
  renderUntaggedCsv,
} from '../report/render.js'

const USAGE = `attest - render CMMC coverage reports from an attestation

Usage:
  attest --input <attestation.json> [--out <dir>] [--update <file.md>] [--check]

Options:
  --input <path>   Attestation written by writeAttestation(). Required.
  --out <dir>      Directory for coverage.md, evidence.csv, untagged.csv.
  --update <path>  Markdown file whose coverage block is replaced in place.
                   The file must already contain the marker pair:
                     <!-- compliant-constructs:coverage:start -->
                     <!-- compliant-constructs:coverage:end -->
  --check          Write nothing; exit 1 if any output would change.
                   Use in CI so stale committed reports fail the build.
  -h, --help       Show this message.

Control claims live in the construct tree and are not serialized into the cloud
assembly, so this reads an attestation produced in-process by writeAttestation()
rather than reading cdk.out directly.
`

interface Options {
  input: string
  out?: string
  update?: string
  check: boolean
}

/** Flags that consume the following argument. */
const VALUE_FLAGS = new Set(['--input', '--out', '--update'])

function assertUsable(options: Partial<Options>): void {
  if (options.input === undefined) throw new Error('--input is required')
  if (options.out === undefined && options.update === undefined) {
    throw new Error('nothing to do: pass --out, --update, or both')
  }
}

export function parseArgs(argv: readonly string[]): Options | 'help' {
  const options: Partial<Options> & { check: boolean } = { check: false }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? ''

    if (arg === '-h' || arg === '--help') return 'help'

    if (arg === '--check') {
      options.check = true
      continue
    }

    // Unknown flags are an error rather than ignored: a typo'd flag that
    // silently did nothing could leave a stale report passing --check.
    if (!VALUE_FLAGS.has(arg)) throw new Error(`unknown argument: ${arg}`)

    const value = argv[i + 1]
    if (value === undefined || value.startsWith('-')) {
      throw new Error(`${arg} requires a value`)
    }

    options[arg.slice(2) as 'input' | 'out' | 'update'] = value
    i++
  }

  assertUsable(options)

  return options as Options
}

/** One file the CLI would write, and whether it differs from what is on disk. */
interface PendingWrite {
  readonly path: string
  readonly contents: string
}

export function plannedWrites(attestation: Attestation, options: Options): PendingWrite[] {
  const writes: PendingWrite[] = []

  if (options.out !== undefined) {
    writes.push(
      { path: join(options.out, 'coverage.md'), contents: renderCoverageMarkdown(attestation) },
      { path: join(options.out, 'evidence.csv'), contents: renderEvidenceCsv(attestation) },
      { path: join(options.out, 'untagged.csv'), contents: renderUntaggedCsv(attestation) }
    )
  }

  if (options.update !== undefined) {
    const existing = readFileSync(options.update, 'utf8')
    writes.push({ path: options.update, contents: injectCoverageTable(existing, attestation) })
  }

  return writes
}

export function main(argv: readonly string[]): number {
  let options: Options | 'help'
  try {
    options = parseArgs(argv)
  } catch (error) {
    console.error(`attest: ${error instanceof Error ? error.message : String(error)}\n`)
    console.error(USAGE)
    return 2
  }

  if (options === 'help') {
    console.warn(USAGE)
    return 0
  }

  const attestation = JSON.parse(readFileSync(options.input, 'utf8')) as Attestation
  const writes = plannedWrites(attestation, options)

  if (options.check) {
    const stale = writes.filter(w => readOrNull(w.path) !== w.contents)
    if (stale.length > 0) {
      console.error('attest: reports are stale:')
      for (const w of stale) console.error(`  ${w.path}`)
      console.error('\nRe-run without --check and commit the result.')
      return 1
    }
    console.warn(`attest: ${writes.length} report(s) up to date`)
    return 0
  }

  for (const w of writes) {
    mkdirSync(dirname(w.path), { recursive: true })
    writeFileSync(w.path, w.contents, 'utf8')
    console.warn(`attest: wrote ${w.path}`)
  }

  return 0
}

function readOrNull(path: string): string | null {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return null
  }
}
