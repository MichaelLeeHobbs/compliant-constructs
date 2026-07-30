import {
  CMMC2_FRAMEWORK_ID,
  CMMC2_PRACTICE_COUNT,
  CMMC2_PRACTICES,
  CMMC2_REVISION,
  cmmc2Claim,
  type Cmmc2Practice,
  type Cmmc2PracticeId,
} from '../src/cmmc2/index.js'

const ids = Object.keys(CMMC2_PRACTICES) as Cmmc2PracticeId[]
const all: Cmmc2Practice[] = ids.map(id => CMMC2_PRACTICES[id])

/**
 * The 14 SP 800-171 families and their requirement counts, restated here
 * independently of the generator so the test is a genuine second opinion
 * rather than a restatement of the code under test.
 */
const EXPECTED_FAMILIES = [
  ['3.1', 'AC', 'Access Control', 22],
  ['3.2', 'AT', 'Awareness and Training', 3],
  ['3.3', 'AU', 'Audit and Accountability', 9],
  ['3.4', 'CM', 'Configuration Management', 9],
  ['3.5', 'IA', 'Identification and Authentication', 11],
  ['3.6', 'IR', 'Incident Response', 3],
  ['3.7', 'MA', 'Maintenance', 6],
  ['3.8', 'MP', 'Media Protection', 9],
  ['3.9', 'PS', 'Personnel Security', 2],
  ['3.10', 'PE', 'Physical Protection', 6],
  ['3.11', 'RA', 'Risk Assessment', 3],
  ['3.12', 'CA', 'Security Assessment', 4],
  ['3.13', 'SC', 'System and Communications Protection', 16],
  ['3.14', 'SI', 'System and Information Integrity', 7],
] as const

describe('CMMC2_PRACTICES catalog', () => {
  it('contains exactly 110 practices', () => {
    expect(ids).toHaveLength(110)
    expect(CMMC2_PRACTICE_COUNT).toBe(110)
  })

  it('keys the record by each practice id', () => {
    for (const id of ids) expect(CMMC2_PRACTICES[id].id).toBe(id)
  })

  it('has no duplicate NIST requirement numbers', () => {
    const reqs = all.map(p => p.nist800171)
    expect(new Set(reqs).size).toBe(reqs.length)
  })

  it('is entirely Level 2 against SP 800-171 rev2', () => {
    for (const p of all) {
      expect(p.level).toBe(2)
      expect(p.revision).toBe('rev2')
    }
  })

  it('carries non-empty verbatim requirement text for every practice', () => {
    for (const p of all) expect(p.title.length).toBeGreaterThan(0)
  })

  it('classifies every requirement as basic or derived', () => {
    for (const p of all) expect(['basic', 'derived']).toContain(p.requirementKind)
  })

  it.each(EXPECTED_FAMILIES)(
    'family %s (%s) has the right domain and requirement count',
    (family, abbrev, domain, count) => {
      const members = all.filter(p => p.nist800171.startsWith(`${family}.`))

      expect(members).toHaveLength(count)
      for (const p of members) {
        expect(p.domainAbbrev).toBe(abbrev)
        expect(p.domain).toBe(domain)
      }
    }
  )

  it.each(EXPECTED_FAMILIES)('family %s numbering is contiguous from 1', family => {
    const ordinals = all
      .filter(p => p.nist800171.startsWith(`${family}.`))
      .map(p => Number(p.nist800171.slice(family.length + 1)))
      .sort((a, b) => a - b)

    expect(ordinals).toEqual(ordinals.map((_, i) => i + 1))
  })

  it('derives every practice id as <DOMAIN>.L2-<requirement>', () => {
    for (const p of all) {
      expect(p.id).toMatch(/^[A-Z]{2}\.L2-3\.\d{1,2}\.\d{1,2}$/)
      expect(p.id).toBe(`${p.domainAbbrev}.L2-${p.nist800171}`)
    }
  })

  // The four domain codes inherited from SP 800-53 rather than the family's
  // own initials. These are precisely where a hand-written catalog goes wrong.
  it.each([
    ['3.10.1', 'PE.L2-3.10.1'],
    ['3.12.1', 'CA.L2-3.12.1'],
    ['3.13.1', 'SC.L2-3.13.1'],
    ['3.14.1', 'SI.L2-3.14.1'],
  ])('maps requirement %s to %s', (requirement, expected) => {
    expect(all.find(p => p.nist800171 === requirement)?.id).toBe(expected)
  })

  it('reproduces NIST requirement text verbatim', () => {
    expect(CMMC2_PRACTICES['SC.L2-3.13.16'].title).toBe(
      'Protect the confidentiality of CUI at rest.'
    )
    expect(CMMC2_PRACTICES['AC.L2-3.1.3'].title).toBe(
      'Control the flow of CUI in accordance with approved authorizations.'
    )
  })
})

describe('cmmc2Claim', () => {
  it('stamps framework, revision and practice id', () => {
    expect(
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Encrypted=true with a customer-managed KMS key',
      })
    ).toEqual({
      framework: CMMC2_FRAMEWORK_ID,
      frameworkRevision: CMMC2_REVISION,
      controlId: 'SC.L2-3.13.16',
      satisfaction: 'partial',
      evidence: 'Encrypted=true with a customer-managed KMS key',
    })
  })

  it('omits optional keys entirely rather than setting them to undefined', () => {
    const claim = cmmc2Claim({
      practice: 'AU.L2-3.3.1',
      satisfaction: 'supporting',
      evidence: 'BackupPolicy=ENABLED',
    })

    expect(Object.keys(claim)).not.toContain('nagRuleIds')
    expect(Object.keys(claim)).not.toContain('caveat')
  })

  it('passes nagRuleIds and caveat through when supplied', () => {
    const claim = cmmc2Claim({
      practice: 'SC.L2-3.13.11',
      satisfaction: 'partial',
      evidence: 'KMS CMK used for all encryption at rest',
      nagRuleIds: ['NIST.800.53.R5-EFSEncrypted'],
      caveat: 'Does not evidence FIPS mode on the client mount.',
    })

    expect(claim.nagRuleIds).toEqual(['NIST.800.53.R5-EFSEncrypted'])
    expect(claim.caveat).toBe('Does not evidence FIPS mode on the client mount.')
  })

  // TypeScript rejects this at compile time; the runtime guard exists for
  // JavaScript consumers, who get no such protection.
  it('rejects an identifier that is not a Level 2 practice', () => {
    expect(() =>
      cmmc2Claim({
        practice: 'SC.L2-9.9.9' as Cmmc2PracticeId,
        satisfaction: 'full',
        evidence: 'x',
      })
    ).toThrow(/not a CMMC 2.0 Level 2 practice/)
  })
})
