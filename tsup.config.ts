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
    'src/cmmc2/aws-cloudtrail/index.ts',
    'src/cmmc2/aws-dynamodb/index.ts',
    'src/cmmc2/aws-ec2/index.ts',
    'src/cmmc2/aws-ecs/index.ts',
    'src/cmmc2/aws-efs/index.ts',
    'src/cmmc2/aws-elasticloadbalancingv2/index.ts',
    'src/cmmc2/aws-kms/index.ts',
    'src/cmmc2/aws-lambda/index.ts',
    'src/cmmc2/aws-logs/index.ts',
    'src/cmmc2/aws-rds/index.ts',
    'src/cmmc2/aws-s3/index.ts',
    'src/cmmc2/aws-secretsmanager/index.ts',
    'src/cmmc2/aws-sns/index.ts',
    'src/cmmc2/aws-sqs/index.ts',
    'src/cmmc2/patterns/index.ts',
  ],
  format: ['esm', 'cjs'],
  // Declarations come from tsc (see tsconfig.build.json), not rollup-plugin-dts.
  // With a dozen entry points each pulling the whole aws-cdk-lib type graph, the
  // dts plugin exhausted the heap in its worker thread - and worker threads do
  // not inherit --max-old-space-size from the parent. tsc emits the same tree
  // for a fraction of the memory, and scales as modules are added.
  dts: false,
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
