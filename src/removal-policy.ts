import { type RemovalPolicy } from 'aws-cdk-lib'

/**
 * Removal policies for resources CloudFormation will not snapshot.
 *
 * `DESTROY` is excluded for the obvious reason. `SNAPSHOT` is excluded because
 * `AWS::S3::Bucket`, `AWS::EFS::FileSystem`, `AWS::KMS::Key` and
 * `AWS::Backup::BackupVault` all reject it - CloudFormation accepts only
 * `Delete`, `Retain` and `RetainExceptOnCreate` on those types, so offering
 * `SNAPSHOT` would let a caller synthesize a template that fails at deploy.
 *
 * Contrast {@link SnapshottableRemovalPolicy}: narrowing has to follow what
 * each resource type actually accepts, which is why there is more than one of
 * these rather than a single library-wide "safe policies" union.
 */
export type NonDestructiveRemovalPolicy =
  RemovalPolicy.RETAIN | RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE

/**
 * Removal policies for resources CloudFormation can snapshot on delete.
 *
 * `AWS::RDS::DBInstance` accepts `Snapshot`, and for a database it is often the
 * right answer: the stack goes away but the data survives in a form you can
 * restore. `DESTROY` remains unrepresentable.
 */
export type SnapshottableRemovalPolicy = NonDestructiveRemovalPolicy | RemovalPolicy.SNAPSHOT
