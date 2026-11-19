/**
 * The S3 lifecycle rule that deletes presentation export files after 7 days.
 *
 *   dotenv -e .env.production -- node scripts/s3-export-lifecycle.js           # show, change nothing
 *   dotenv -e .env.production -- node scripts/s3-export-lifecycle.js --apply   # add / update the rule
 *
 * The rule expires everything under `presentation-exports/` (PPT_EXPORT_S3_PREFIX) after
 * PPT_EXPORT_RETENTION_DAYS days (default 7). The bucket's other lifecycle rules are kept: S3
 * replaces the whole rule list on every write, so the script reads it, swaps in this one rule
 * (by its ID) and writes it back. Needs s3:GetLifecycleConfiguration and
 * s3:PutLifecycleConfiguration on AWS_S3_BUCKET.
 *
 * Exports made before this change sit under `presentations/<workspace>/<deck>/exports/`, which a
 * rule can't match (the wildcard is in the middle). `--legacy` lists those older than the
 * retention period; `--legacy --delete-legacy` deletes them.
 */
const {
  GetBucketLifecycleConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
  ListObjectsV2Command,
  DeleteObjectsCommand,
} = require('@aws-sdk/client-s3');
// The app's own S3 client (same region and credentials).
const s3 = require('../src/shared/config/s3');
const {
  exportLifecycleRule,
  mergeLifecycleRules,
  exportRetentionDays,
} = require('../src/modules/presentation/exportStorage');

const args = new Set(process.argv.slice(2));
const bucket = process.env.AWS_S3_BUCKET;

async function currentRules() {
  try {
    const res = await s3.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket }));
    return res.Rules || [];
  } catch (err) {
    if (err?.name === 'NoSuchLifecycleConfiguration' || err?.Code === 'NoSuchLifecycleConfiguration') return [];
    throw err;
  }
}

async function legacyExports({ remove }) {
  const cutoff = Date.now() - exportRetentionDays() * 24 * 60 * 60 * 1000;
  const old = [];
  let token;
  do {
    const page = await s3.send(
      new ListObjectsV2Command({ Bucket: bucket, Prefix: 'presentations/', ContinuationToken: token })
    );
    for (const obj of page.Contents || []) {
      if (/^presentations\/[^/]+\/[^/]+\/exports\//.test(obj.Key) && new Date(obj.LastModified).getTime() < cutoff) {
        old.push(obj.Key);
      }
    }
    token = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (token);
  console.log(`Old-layout export files older than ${exportRetentionDays()} days: ${old.length}`);
  old.slice(0, 10).forEach((key) => console.log(`  ${key}`));
  if (old.length > 10) console.log(`  … and ${old.length - 10} more`);
  if (!remove || !old.length) return;
  for (let i = 0; i < old.length; i += 1000) {
    const batch = old.slice(i, i + 1000);
    await s3.send(
      new DeleteObjectsCommand({ Bucket: bucket, Delete: { Objects: batch.map((Key) => ({ Key })), Quiet: true } })
    );
  }
  console.log(`Deleted ${old.length} old-layout export files.`);
}

async function main() {
  if (!bucket) throw new Error('AWS_S3_BUCKET is not set');
  const rule = exportLifecycleRule();
  const existing = await currentRules();
  const current = existing.find((r) => r.ID === rule.ID);

  console.log(`Bucket: ${bucket}`);
  console.log(`Other lifecycle rules kept: ${existing.filter((r) => r.ID !== rule.ID).length}`);
  console.log(`Export rule now: ${current ? JSON.stringify(current) : 'none'}`);
  console.log(`Export rule wanted: ${JSON.stringify(rule)}`);

  if (args.has('--apply')) {
    await s3.send(
      new PutBucketLifecycleConfigurationCommand({
        Bucket: bucket,
        LifecycleConfiguration: { Rules: mergeLifecycleRules(existing, rule) },
      })
    );
    console.log('Applied.');
  } else {
    console.log('Dry run: nothing changed. Add --apply to write the rule.');
  }

  if (args.has('--legacy')) await legacyExports({ remove: args.has('--delete-legacy') });
}

main().catch((err) => {
  console.error(err?.message || err);
  process.exit(1);
});
