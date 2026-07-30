import { RemovalPolicy } from 'aws-cdk-lib'
import type * as ec2 from 'aws-cdk-lib/aws-ec2'
import type * as kms from 'aws-cdk-lib/aws-kms'

import { FileSystem, type FileSystemProps } from '../src/cmmc2/aws-efs/index.js'
import { type CompliantStack, type CompliantStackProps } from '../src/cmmc2/index.js'

/**
 * Negative type tests.
 *
 * Every `@ts-expect-error` below fails `tsc --noEmit` if the line it precedes
 * stops being an error - so this file asserts that non-compliant configurations
 * remain unrepresentable. Without it there is no proof the narrowing works, and
 * an `Omit` that silently stopped matching an upstream prop would go unnoticed.
 *
 * Checked by `pnpm run test:types`. This file is deliberately NOT a jest module:
 * it declares its subjects with `declare const`, which has no runtime value, so
 * executing it would throw. tsconfig includes tests/**, so tsc checks it.
 */

declare const vpc: ec2.IVpc
declare const kmsKey: kms.IKey
declare const scope: CompliantStack

const base = { vpc, vpcSubnets: { subnets: vpc.privateSubnets }, kmsKey }

// --- props the wrapper takes ownership of cannot be supplied at all ---

// @ts-expect-error encryption cannot be disabled
const _noEncryption: FileSystemProps = { ...base, encrypted: false }

// @ts-expect-error encryption cannot even be restated
const _restateEncryption: FileSystemProps = { ...base, encrypted: true }

// @ts-expect-error anonymous access cannot be enabled
const _anonymous: FileSystemProps = { ...base, allowAnonymousAccess: true }

// @ts-expect-error automatic backups cannot be turned off
const _noBackups: FileSystemProps = { ...base, enableAutomaticBackups: false }

// @ts-expect-error the resource policy is owned by the construct
const _ownPolicy: FileSystemProps = { ...base, fileSystemPolicy: undefined }

// --- required props cannot be omitted ---

// @ts-expect-error kmsKey is required, unlike in the CDK
const _noKey: FileSystemProps = { vpc, vpcSubnets: { subnets: vpc.privateSubnets } }

// @ts-expect-error vpcSubnets is required, unlike in the CDK
const _noSubnets: FileSystemProps = { vpc, kmsKey }

// --- removal policy is narrowed to the values EFS actually accepts ---

// @ts-expect-error DESTROY would delete CUI on stack teardown
const _destroy: FileSystemProps = { ...base, removalPolicy: RemovalPolicy.DESTROY }

// @ts-expect-error SNAPSHOT is not valid for AWS::EFS::FileSystem
const _snapshot: FileSystemProps = { ...base, removalPolicy: RemovalPolicy.SNAPSHOT }

const _retain: FileSystemProps = { ...base, removalPolicy: RemovalPolicy.RETAIN }
const _retainOnUpdate: FileSystemProps = {
  ...base,
  removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
}

// --- the stack requires typed tags and rejects the free-form map ---

// @ts-expect-error requiredTags cannot be omitted
const _untagged: CompliantStackProps = {}

const _freeformTags: CompliantStackProps = {
  requiredTags: { project: 'p', owner: 'o', environment: 'e', containsCui: true },
  // @ts-expect-error StackProps.tags is replaced, not supplemented
  tags: { Project: 'p' },
}

const _stringCui: CompliantStackProps = {
  // @ts-expect-error containsCui is a boolean, not a string
  requiredTags: { project: 'p', owner: 'o', environment: 'e', containsCui: 'true' },
}

// --- the compliant shape does compile ---

const _valid: FileSystemProps = base
const _construct = (): FileSystem => new FileSystem(scope, 'Fs', base)

void [
  _noEncryption,
  _restateEncryption,
  _anonymous,
  _noBackups,
  _ownPolicy,
  _noKey,
  _noSubnets,
  _destroy,
  _snapshot,
  _retain,
  _retainOnUpdate,
  _untagged,
  _freeformTags,
  _stringCui,
  _valid,
  _construct,
]
