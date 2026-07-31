/**
 * Emit legacy-resolution stub directories for every published subpath.
 *
 * Why this exists: `cdk init app --language typescript` still generates a
 * tsconfig with `"module": "commonjs"` and no `moduleResolution`, which means
 * TypeScript's classic node10 resolution. node10 resolution ignores the
 * "exports" map entirely, so `@ubercode/compliant-constructs/cmmc2` would fail
 * to resolve for a default CDK project - our single most likely consumer.
 *
 * The fix is the well-trodden one: ship a real directory at the package root
 * for each subpath, containing a tiny package.json that points back into
 * dist/. node10 and TypeScript classic resolution both understand that;
 * modern resolvers never see it because "exports" takes precedence.
 *
 * The subpath list is derived from package.json "exports" so the two can
 * never drift.
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))

/** Subpaths that need a stub: everything except the root and package.json itself. */
const subpaths = Object.entries(pkg.exports ?? {}).filter(
  ([key, value]) => key !== '.' && key !== './package.json' && typeof value === 'object'
)

if (subpaths.length === 0) {
  console.warn('gen-subpath-stubs: no subpath exports found, nothing to do')
}

for (const [subpath, conditions] of subpaths) {
  // './cmmc2' -> 'cmmc2'
  const dir = join(root, subpath.replace(/^\.\//, ''))
  await mkdir(dir, { recursive: true })

  // Targets in the exports map are package-root-relative ('./dist/cmmc2/index.js').
  // The stub package.json lives in `dir`, so rewrite them relative to that.
  const toStubRelative = target => {
    const abs = join(root, target.replace(/^\.\//, ''))
    return relative(dir, abs).split('\\').join('/')
  }

  const stub = {
    name: `${pkg.name}${subpath.replace(/^\./, '')}`,
    private: true,
    types: toStubRelative(conditions.types),
    main: toStubRelative(conditions.require),
    module: toStubRelative(conditions.import),
    sideEffects: false,
  }

  await writeFile(join(dir, 'package.json'), `${JSON.stringify(stub, null, 2)}\n`, 'utf8')
  console.warn(`gen-subpath-stubs: wrote ${relative(root, join(dir, 'package.json'))}`)
}

/*
 * A stub nobody publishes is worse than no stub: the subpath silently works in
 * development and fails for consumers. `verify/` and `report/` shipped that way
 * because "files" listed `cmmc2/` by name, so every subpath added outside that
 * directory was quietly excluded. Fail the build rather than let it happen
 * again.
 */
const published = new Set((pkg.files ?? []).map(entry => entry.replace(/\/$/, '')))
const missing = subpaths
  .map(([subpath]) => subpath.replace(/^\.\//, '').split('/')[0])
  .filter(top => !published.has(top))

if (missing.length > 0) {
  console.error(
    `gen-subpath-stubs: these stub directories are not in package.json "files", so they would ` +
      `not be published and the subpath would fail to resolve for anyone on classic node ` +
      `resolution: ${[...new Set(missing)].join(', ')}`
  )
  process.exit(1)
}
