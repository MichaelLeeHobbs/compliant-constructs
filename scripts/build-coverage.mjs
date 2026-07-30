/**
 * Generate this library's own coverage documentation.
 *
 * Builds a reference app containing every construct the library ships, collects
 * the control claims from the resulting construct tree, and renders the report
 * set through the `attest` CLI - so the CLI is exercised on every docs build
 * rather than only in tests.
 *
 * Runs against `dist/`, not `src/`, so what gets documented is what gets
 * published. Requires `pnpm run build` first.
 *
 * Pass `--check` to fail instead of writing, for CI.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const docsDir = join(root, 'docs')
const attestationPath = join(docsDir, 'attestation.json')

const { App } = await import('aws-cdk-lib')
const ec2 = await import('aws-cdk-lib/aws-ec2')
const kms = await import('aws-cdk-lib/aws-kms')

const { CompliantStack } = await import('../dist/cmmc2/index.mjs')
const { FileSystem } = await import('../dist/cmmc2/aws-efs/index.mjs')
const { EncryptedFileSystem } = await import('../dist/cmmc2/patterns/index.mjs')
const { buildAttestation } = await import('../dist/report/index.mjs')
const { verifyCompliance } = await import('../dist/verify.mjs')
const { main } = await import('../dist/cli/attest.mjs')

/**
 * A reference deployment exercising every construct the library ships.
 *
 * The VPC is imported rather than created: a real `ec2.Vpc` would add subnets,
 * route tables and a gateway whose claims are not this library's to make.
 */
function referenceApp() {
  const app = new App()
  const stack = new CompliantStack(app, 'ReferenceStack', {
    env: { account: '111111111111', region: 'us-east-1' },
    requiredTags: {
      project: 'reference',
      owner: 'platform',
      environment: 'prod',
      containsCui: true,
    },
  })

  const vpc = ec2.Vpc.fromVpcAttributes(stack, 'Vpc', {
    vpcId: 'vpc-0aa11bb22cc33dd44',
    availabilityZones: ['us-east-1a', 'us-east-1b'],
    privateSubnetIds: ['subnet-0aa11bb22cc33dd01', 'subnet-0aa11bb22cc33dd02'],
    privateSubnetRouteTableIds: ['rtb-0aa11bb22cc33dd01', 'rtb-0aa11bb22cc33dd02'],
  })
  const vpcSubnets = { subnets: vpc.privateSubnets }

  new EncryptedFileSystem(stack, 'CuiStorage', {
    vpc,
    vpcSubnets,
    fileSystemName: 'reference-cui',
  })

  const key = new kms.Key(stack, 'StandaloneKey', { enableKeyRotation: true })
  new FileSystem(stack, 'StandaloneFileSystem', { vpc, vpcSubnets, kmsKey: key })

  return stack
}

const stack = referenceApp()
const { violations } = verifyCompliance(stack)
const attestation = buildAttestation(stack, { violations })

const check = process.argv.includes('--check')
const serialized = `${JSON.stringify(attestation, null, 2)}\n`

if (!check) {
  mkdirSync(docsDir, { recursive: true })
  writeFileSync(attestationPath, serialized, 'utf8')
}

const argv = [
  '--input',
  attestationPath,
  '--out',
  docsDir,
  '--update',
  join(root, 'README.md'),
  ...(check ? ['--check'] : []),
]

const code = main(argv)

if (check && code === 0) {
  // The CLI checked the rendered reports; the attestation itself still has to
  // match, or a claim could change without any rendered output moving.
  const { readFileSync } = await import('node:fs')
  const onDisk = readFileSync(attestationPath, 'utf8')
  if (onDisk !== serialized) {
    console.error(`attest: ${attestationPath} is stale. Run \`pnpm run coverage:build\`.`)
    process.exit(1)
  }
}

process.exit(code)
