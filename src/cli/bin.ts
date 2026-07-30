#!/usr/bin/env node
/**
 * Executable entry for the `attest` CLI.
 *
 * Kept separate from `attest.ts` so that module stays free of side effects and
 * can be imported by tests. A `require.main === module` guard would not work
 * here: this package ships both CommonJS and ESM builds, and `require.main` is
 * meaningless in the ESM one.
 */
import { main } from './attest.js'

process.exitCode = main(process.argv.slice(2))
