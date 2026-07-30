import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { main, parseArgs } from '../src/cli/attest.js'
import {
  README_MARKER_END,
  README_MARKER_START,
  buildAttestation,
  renderCoverageMarkdown,
} from '../src/report/index.js'
import { EncryptedFileSystem } from '../src/cmmc2/patterns/index.js'
import { testStack } from './helpers/fixtures.js'

/** A temp dir holding an attestation.json, as writeAttestation would leave it. */
function fixture(): { dir: string; input: string } {
  const dir = mkdtempSync(join(tmpdir(), 'attest-cli-'))
  const { stack, vpc } = testStack()
  new EncryptedFileSystem(stack, 'CuiStorage', {
    vpc,
    vpcSubnets: { subnets: vpc.privateSubnets },
    fileSystemName: 'cui',
  })

  const input = join(dir, 'attestation.json')
  writeFileSync(input, `${JSON.stringify(buildAttestation(stack), null, 2)}\n`, 'utf8')

  return { dir, input }
}

const quiet = {
  warn: jest.spyOn(console, 'warn').mockImplementation(() => undefined),
  error: jest.spyOn(console, 'error').mockImplementation(() => undefined),
}

afterEach(() => {
  quiet.warn.mockClear()
  quiet.error.mockClear()
})

describe('parseArgs', () => {
  it('accepts the documented flags', () => {
    expect(parseArgs(['--input', 'a.json', '--out', 'docs', '--check'])).toEqual({
      input: 'a.json',
      out: 'docs',
      check: true,
    })
  })

  it('returns help for -h and --help', () => {
    expect(parseArgs(['-h'])).toBe('help')
    expect(parseArgs(['--help'])).toBe('help')
  })

  it('requires --input', () => {
    expect(() => parseArgs(['--out', 'docs'])).toThrow(/--input is required/)
  })

  it('refuses to run with nothing to do', () => {
    expect(() => parseArgs(['--input', 'a.json'])).toThrow(/nothing to do/)
  })

  it('rejects a flag used as a value', () => {
    expect(() => parseArgs(['--input', '--out'])).toThrow(/--input requires a value/)
  })

  it('rejects unknown arguments rather than ignoring them', () => {
    expect(() => parseArgs(['--input', 'a.json', '--wat'])).toThrow(/unknown argument: --wat/)
  })
})

describe('attest --out', () => {
  it('writes the three reports and exits 0', () => {
    const { dir, input } = fixture()
    const out = join(dir, 'reports')

    expect(main(['--input', input, '--out', out])).toBe(0)
    expect(readFileSync(join(out, 'coverage.md'), 'utf8')).toContain('# CMMC 2.0 Level 2 coverage')
    expect(readFileSync(join(out, 'evidence.csv'), 'utf8')).toContain('practice,domain,')
    expect(readFileSync(join(out, 'untagged.csv'), 'utf8')).toContain('AWS::EFS::MountTarget')
  })

  it('renders the same content the library would', () => {
    const { dir, input } = fixture()
    const out = join(dir, 'reports')
    main(['--input', input, '--out', out])

    const model = JSON.parse(readFileSync(input, 'utf8'))

    expect(readFileSync(join(out, 'coverage.md'), 'utf8')).toBe(renderCoverageMarkdown(model))
  })
})

describe('attest --update', () => {
  it('replaces the marked block in place', () => {
    const { dir, input } = fixture()
    const readme = join(dir, 'README.md')
    writeFileSync(readme, `# Doc\n\n${README_MARKER_START}\nold\n${README_MARKER_END}\n\ntail\n`)

    expect(main(['--input', input, '--update', readme])).toBe(0)

    const updated = readFileSync(readme, 'utf8')
    expect(updated).not.toContain('old')
    expect(updated).toContain('# Doc')
    expect(updated).toContain('tail')
    expect(updated).toMatch(/\|\s+\*\*Total\*\*\s+\|/)
  })
})

describe('attest --check', () => {
  it('exits 0 when reports are current and writes nothing', () => {
    const { dir, input } = fixture()
    const out = join(dir, 'reports')
    main(['--input', input, '--out', out])

    const before = readFileSync(join(out, 'coverage.md'), 'utf8')

    expect(main(['--input', input, '--out', out, '--check'])).toBe(0)
    expect(readFileSync(join(out, 'coverage.md'), 'utf8')).toBe(before)
  })

  it('exits 1 when a report is stale, without overwriting it', () => {
    const { dir, input } = fixture()
    const out = join(dir, 'reports')
    main(['--input', input, '--out', out])
    writeFileSync(join(out, 'coverage.md'), 'tampered\n')

    expect(main(['--input', input, '--out', out, '--check'])).toBe(1)
    expect(readFileSync(join(out, 'coverage.md'), 'utf8')).toBe('tampered\n')
  })

  it('exits 1 when a report is missing entirely', () => {
    const { dir, input } = fixture()

    expect(main(['--input', input, '--out', join(dir, 'never-written'), '--check'])).toBe(1)
  })
})

describe('attest error handling', () => {
  it('exits 2 with usage on a bad invocation', () => {
    expect(main(['--nonsense'])).toBe(2)
    expect(quiet.error).toHaveBeenCalled()
  })

  it('exits 0 for --help', () => {
    expect(main(['--help'])).toBe(0)
  })
})
