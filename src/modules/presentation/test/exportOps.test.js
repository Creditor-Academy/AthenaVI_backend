'use strict';

// Export storage (S3 keys, 7-day retention, the lifecycle rule) and export metrics (last-hour
// summary, failure-rate alert). Pure: no DB, S3 or browser.

const assert = require('assert');
const { test, beforeEach } = require('node:test');

const storage = require('../exportStorage');
const metrics = require('../exportMetrics');
const logger = require('../../../shared/utils/logger');

const DAY = 24 * 60 * 60 * 1000;

// ── Storage ───────────────────────────────────────────────────────────────────

test('export files live under one prefix that a lifecycle rule can match', () => {
  assert.equal(
    storage.exportS3Key({ workspaceId: 'w1', deckId: 'd1', exportId: 'e1', ext: 'pptx' }),
    'presentation-exports/w1/d1/e1.pptx'
  );
  process.env.PPT_EXPORT_S3_PREFIX = '/custom-exports/';
  try {
    assert.equal(storage.exportS3Key({ workspaceId: 'w', deckId: 'd', exportId: 'e', ext: 'pdf' }), 'custom-exports/w/d/e.pdf');
    assert.deepEqual(storage.exportLifecycleRule().Filter, { Prefix: 'custom-exports/' });
  } finally {
    delete process.env.PPT_EXPORT_S3_PREFIX;
  }
});

test('the lifecycle rule expires export files after 7 days (configurable)', () => {
  const rule = storage.exportLifecycleRule();
  assert.equal(rule.ID, storage.LIFECYCLE_RULE_ID);
  assert.equal(rule.Status, 'Enabled');
  assert.deepEqual(rule.Filter, { Prefix: 'presentation-exports/' });
  assert.deepEqual(rule.Expiration, { Days: 7 });
  process.env.PPT_EXPORT_RETENTION_DAYS = '3';
  try {
    assert.deepEqual(storage.exportLifecycleRule().Expiration, { Days: 3 });
  } finally {
    delete process.env.PPT_EXPORT_RETENTION_DAYS;
  }
});

test('merging keeps the bucket’s other rules and replaces only the export rule', () => {
  const other = { ID: 'tmp-uploads', Status: 'Enabled', Filter: { Prefix: 'tmp/' }, Expiration: { Days: 1 } };
  const oldExport = { ID: storage.LIFECYCLE_RULE_ID, Status: 'Enabled', Filter: { Prefix: 'x/' }, Expiration: { Days: 30 } };
  const merged = storage.mergeLifecycleRules([other, oldExport]);
  assert.equal(merged.length, 2);
  assert.deepEqual(merged[0], other);
  assert.deepEqual(merged[1], storage.exportLifecycleRule());
  assert.deepEqual(storage.mergeLifecycleRules([]), [storage.exportLifecycleRule()]);
  assert.deepEqual(storage.mergeLifecycleRules(undefined), [storage.exportLifecycleRule()]);
});

test('a ready export expires after the retention period (an hour early, never a link to a vanishing file)', () => {
  const now = Date.now();
  const ready = (ageMs) => ({ status: 'READY', updatedAt: new Date(now - ageMs) });
  assert.equal(storage.isExportExpired(ready(6 * DAY), now), false);
  assert.equal(storage.isExportExpired(ready(7 * DAY - 30 * 60 * 1000), now), true);
  assert.equal(storage.isExportExpired(ready(8 * DAY), now), true);
  assert.equal(storage.isExportExpired({ status: 'FAILED', updatedAt: new Date(now - 30 * DAY) }, now), false);
  assert.equal(storage.isExportExpired(null, now), false);
});

// ── Metrics ───────────────────────────────────────────────────────────────────

beforeEach(() => metrics.reset());

/** Error log lines written while `fn` runs. */
function captureErrors(fn) {
  const lines = [];
  const original = logger.error;
  logger.error = (event, data) => lines.push({ event, data });
  try {
    fn();
  } finally {
    logger.error = original;
  }
  return lines;
}

test('metrics: last-hour counts, failure rate without cancels, durations and top reasons', () => {
  const now = Date.now();
  for (let i = 0; i < 8; i += 1) metrics.recordExport({ outcome: 'READY', format: 'PPTX', durationMs: (i + 1) * 1000 }, now);
  metrics.recordExport({ outcome: 'READY', format: 'pdf', durationMs: 4000 }, now);
  metrics.recordExport({ outcome: 'FAILED', format: 'PDF', reason: 'The export stopped unexpectedly. Please try again.' }, now);
  metrics.recordExport({ outcome: 'CANCELLED', format: 'PNG' }, now);
  const s = metrics.snapshot(now);
  assert.equal(s.windowMinutes, 60);
  assert.equal(s.total, 11);
  assert.equal(s.ready, 9);
  assert.equal(s.failed, 1);
  assert.equal(s.cancelled, 1);
  assert.equal(s.failureRate, 0.1, 'cancels are not failures');
  assert.equal(s.byFormat.PPTX.ready, 8);
  assert.equal(s.byFormat.PPTX.p50Ms, 4000);
  assert.equal(s.byFormat.PPTX.p95Ms, 8000);
  assert.equal(s.byFormat.PDF.failed, 1);
  assert.deepEqual(s.topReasons, [{ reason: 'The export stopped unexpectedly. Please try again.', count: 1 }]);
});

test('metrics: exports older than an hour drop out', () => {
  const now = Date.now();
  metrics.recordExport({ outcome: 'FAILED', format: 'PDF', reason: 'x' }, now - 61 * 60 * 1000);
  metrics.recordExport({ outcome: 'READY', format: 'PDF', durationMs: 1 }, now);
  const s = metrics.snapshot(now);
  assert.equal(s.total, 1);
  assert.equal(s.failed, 0);
});

test('alert: above 5% failures in the hour, once enough exports finished, then quiet for 15 minutes', () => {
  let now = Date.now();
  // 18 good, then failures: no alert until 20 exports have finished.
  for (let i = 0; i < 18; i += 1) metrics.recordExport({ outcome: 'READY', format: 'PPTX', durationMs: 1000 }, now);
  let errors = captureErrors(() => metrics.recordExport({ outcome: 'FAILED', format: 'PPTX', reason: 'r1' }, now));
  assert.equal(errors.length, 0, '19 finished: too few to judge');
  errors = captureErrors(() => metrics.recordExport({ outcome: 'FAILED', format: 'PDF', reason: 'r1' }, now));
  assert.equal(errors.length, 1, '2 of 20 failed (10%)');
  assert.equal(errors[0].event, 'presentation_export_failure_rate_high');
  assert.equal(errors[0].data.failed, 2);
  assert.equal(errors[0].data.finished, 20);
  assert.equal(errors[0].data.threshold, 0.05);
  assert.deepEqual(errors[0].data.topReasons, [{ reason: 'r1', count: 2 }]);

  // Within the cooldown: no second alert.
  now += 5 * 60 * 1000;
  errors = captureErrors(() => metrics.recordExport({ outcome: 'FAILED', format: 'PDF', reason: 'r2' }, now));
  assert.equal(errors.length, 0);
  // After it: alerts again while the rate stays high.
  now += 11 * 60 * 1000;
  errors = captureErrors(() => metrics.recordExport({ outcome: 'FAILED', format: 'PDF', reason: 'r2' }, now));
  assert.equal(errors.length, 1);
});

test('alert: 1 failure in 40 (2.5%) is below the threshold', () => {
  const now = Date.now();
  for (let i = 0; i < 39; i += 1) metrics.recordExport({ outcome: 'READY', format: 'PDF', durationMs: 1 }, now);
  const errors = captureErrors(() => metrics.recordExport({ outcome: 'FAILED', format: 'PDF', reason: 'r' }, now));
  assert.equal(errors.length, 0);
});
