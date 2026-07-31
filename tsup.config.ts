import { defineConfig } from 'tsup'

export default defineConfig({
  // One entry per published subpath. Keep this list in sync with the "exports"
  // map in package.json - scripts/gen-subpath-stubs.mjs reads that map to emit
  // the legacy-resolution stub directories and will fail loudly on a mismatch.
  entry: [
    'src/index.ts',
    'src/verify.ts',
    'src/report/index.ts',
    'src/cli/attest.ts',
    'src/cli/bin.ts',
    'src/cmmc2/index.ts',
    'src/cmmc2/aws-efs/index.ts',
    'src/cmmc2/aws-rds/index.ts',
    'src/cmmc2/aws-s3/index.ts',
    'src/cmmc2/patterns/index.ts',
  ],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  // Shared internals are small; duplicating them per entry keeps the output
  // tree predictable and avoids chunk files that the stub directories would
  // have to know about.
  splitting: false,
  treeshake: true,
  minify: false,
  target: 'es2022',
  outDir: 'dist',
  shims: true,
})
