import {
  CMMC2_FRAMEWORK_ID,
  CMMC2_PRACTICES,
  cmmc2Claim,
  type Cmmc2PracticeId,
} from '../src/cmmc2/index.js'

describe('CMMC2_PRACTICES catalog', () => {
  const ids = Object.keys(CMMC2_PRACTICES) as Cmmc2PracticeId[]

  it('is not empty', () => {
    expect(ids.length).toBeGreaterThan(0)
  })

  it.each(ids)('%s has an id field matching its catalog key', id => {
    expect(CMMC2_PRACTICES[id].id).toBe(id)
  })

  it.each(ids)('%s carries a domain, title and NIST SP 800-171 mapping', id => {
    const practice = CMMC2_PRACTICES[id]

    expect(practice.domain).not.toBe('')
    expect(practice.title).not.toBe('')
    expect(practice.level).toBe(2)
    // Level 2 practice IDs embed their 800-171 requirement number, e.g.
    // 'SC.L2-3.13.16' -> '3.13.16'. A mismatch means the catalog entry was
    // transcribed wrong, which would silently corrupt every generated report.
    expect(id.endsWith(practice.nist800171)).toBe(true)
  })
})

describe('cmmc2Claim', () => {
  it('stamps the framework id and carries the practice through as controlId', () => {
    expect(
      cmmc2Claim({
        practice: 'SC.L2-3.13.16',
        satisfaction: 'partial',
        evidence: 'Encrypted=true with a customer-managed KMS key',
      })
    ).toEqual({
      framework: CMMC2_FRAMEWORK_ID,
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
      evidence: 'KMS CMK in a FIPS 140-validated region endpoint',
      nagRuleIds: ['NIST.800.53.R5-EFSEncrypted'],
      caveat: 'Does not evidence FIPS mode on the client mount.',
    })

    expect(claim.nagRuleIds).toEqual(['NIST.800.53.R5-EFSEncrypted'])
    expect(claim.caveat).toBe('Does not evidence FIPS mode on the client mount.')
  })
})
