/**
 * Where presentation export files live in S3, and how long they are kept.
 *
 * Export files sit under one top-level prefix (`presentation-exports/` by default) so that a
 * single S3 lifecycle rule can delete them after PPT_EXPORT_RETENTION_DAYS (default 7). A
 * lifecycle rule matches a key prefix only, so the older `presentations/<ws>/<deck>/exports/…`
 * layout (a wildcard in the middle) could not be expired by a rule.
 *
 * Download links are presigned for an hour; asking for the export again issues a fresh one.
 * Apply the rule with `node scripts/s3-export-lifecycle.js --apply` (see that script).
 */

const envNumber = (name, fallback) => (Number(process.env[name]) > 0 ? Number(process.env[name]) : fallback);

const LIFECYCLE_RULE_ID = 'presentation-exports-expire';

function exportKeyPrefix() {
  const raw = String(process.env.PPT_EXPORT_S3_PREFIX || 'presentation-exports').trim();
  return raw.replace(/^\/+|\/+$/g, '') || 'presentation-exports';
}

function exportRetentionDays() {
  return Math.floor(envNumber('PPT_EXPORT_RETENTION_DAYS', 7));
}

/** S3 key of an export file. */
function exportS3Key({ workspaceId, deckId, exportId, ext }) {
  return `${exportKeyPrefix()}/${workspaceId}/${deckId}/${exportId}.${ext}`;
}

/**
 * The file is past its retention (S3 has deleted it, or will at any moment). Judged from when
 * the export finished (`updatedAt`), with an hour's margin so a link is never handed out for a
 * file about to disappear.
 */
function isExportExpired(row, now = Date.now()) {
  if (!row || row.status !== 'READY') return false;
  const finished = new Date(row.updatedAt || row.createdAt || now).getTime();
  return now - finished > exportRetentionDays() * 24 * 60 * 60 * 1000 - 60 * 60 * 1000;
}

/** The S3 lifecycle rule that deletes export files after the retention period. */
function exportLifecycleRule() {
  return {
    ID: LIFECYCLE_RULE_ID,
    Status: 'Enabled',
    Filter: { Prefix: `${exportKeyPrefix()}/` },
    Expiration: { Days: exportRetentionDays() },
    AbortIncompleteMultipartUpload: { DaysAfterInitiation: 1 },
  };
}

/**
 * The bucket's lifecycle rules with the export rule added or replaced. Every other rule is kept
 * as it is (PutBucketLifecycleConfiguration replaces the whole list).
 */
function mergeLifecycleRules(existing = [], rule = exportLifecycleRule()) {
  const others = (existing || []).filter((r) => r && r.ID !== rule.ID);
  return [...others, rule];
}

module.exports = {
  LIFECYCLE_RULE_ID,
  exportKeyPrefix,
  exportRetentionDays,
  exportS3Key,
  isExportExpired,
  exportLifecycleRule,
  mergeLifecycleRules,
};
