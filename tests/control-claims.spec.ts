import { App, Stack } from 'aws-cdk-lib'
import { Construct } from 'constructs'

import {
  CONTROL_CLAIM_METADATA_KEY,
  addControlClaims,
  collectControlClaims,
  type ControlClaim,
} from '../src/index.js'

const claim = (controlId: string): ControlClaim => ({
  framework: 'test',
  controlId,
  satisfaction: 'full',
  evidence: `evidence for ${controlId}`,
})

describe('addControlClaims / collectControlClaims', () => {
  it('records a claim as construct metadata under the documented key', () => {
    const stack = new Stack(new App(), 'TestStack')
    addControlClaims(stack, [claim('A-1')])

    const entries = stack.node.metadata.filter(e => e.type === CONTROL_CLAIM_METADATA_KEY)

    expect(entries).toHaveLength(1)
    expect(entries[0]?.data).toEqual(claim('A-1'))
  })

  it('collects claims from nested constructs and reports their construct paths', () => {
    const stack = new Stack(new App(), 'TestStack')
    const child = new Construct(stack, 'Storage')
    const grandchild = new Construct(child, 'FileSystem')

    addControlClaims(grandchild, [claim('A-1'), claim('A-2')])

    expect(collectControlClaims(stack)).toEqual([
      { path: 'TestStack/Storage/FileSystem', claim: claim('A-1') },
      { path: 'TestStack/Storage/FileSystem', claim: claim('A-2') },
    ])
  })

  it('preserves declaration order within a construct so reports diff cleanly', () => {
    const stack = new Stack(new App(), 'TestStack')
    addControlClaims(stack, [claim('C'), claim('A'), claim('B')])

    expect(collectControlClaims(stack).map(c => c.claim.controlId)).toEqual(['C', 'A', 'B'])
  })

  it('ignores unrelated construct metadata', () => {
    const stack = new Stack(new App(), 'TestStack')
    stack.node.addMetadata('something:else', { not: 'a claim' })

    expect(collectControlClaims(stack)).toEqual([])
  })

  it('returns an empty list for a tree with no claims', () => {
    const stack = new Stack(new App(), 'TestStack')
    new Construct(stack, 'Empty')

    expect(collectControlClaims(stack)).toEqual([])
  })
})
