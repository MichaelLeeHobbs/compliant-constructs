import type * as s3 from 'aws-cdk-lib/aws-s3'

/**
 * A bucket reference, accepting either the interface or the concrete class.
 *
 * aws-cdk-lib declares `Bucket.isWebsite` optional but `IBucket.isWebsite`
 * required, so a `Bucket` is not assignable to an `IBucket` under
 * `exactOptionalPropertyTypes` - which would make every caller compiling with
 * that flag write a cast. A `Bucket` is an `IBucket`; the friction is absorbed
 * here instead.
 */
export type BucketReference = s3.IBucket | s3.Bucket
