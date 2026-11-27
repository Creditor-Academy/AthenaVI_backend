'use strict';

/**
 * Image links stay the same between fetches within a signing window (CANVAS_FIX_PLAN, R-1), so a
 * review page doesn't re-download every image (and show blanks) each time the deck changes.
 */
const assert = require('assert');
const { test } = require('node:test');

const BUCKET = 'stable-links-bucket';
process.env.AWS_S3_BUCKET = process.env.AWS_S3_BUCKET || BUCKET;
process.env.AWS_REGION = process.env.AWS_REGION || 'us-east-1';
// Presigning is local crypto: placeholder keys are enough (no request is sent).
process.env.AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID || 'AKIATESTPLACEHOLDER0';
process.env.AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY || 'test-secret-placeholder';

const s3Service = require('../../s3/s3.service');
const { attachPresignedMedia, signingWindow, PRESIGN_TTL_SECONDS } = require('../presignSlideMedia');

const bucket = process.env.AWS_S3_BUCKET;
const region = process.env.AWS_REGION;
const slide = () => ({
  id: 's1',
  elements: {
    version: 1,
    elements: [{ id: 'img1', type: 'image', content: { url: `https://${bucket}.s3.${region}.amazonaws.com/w/assets/a.png` } }],
  },
});

test('the signing window covers the full link life from any moment inside it', () => {
  const t = Date.UTC(2026, 10, 26, 10, 17, 3);
  const w = signingWindow(t);
  assert.ok(w.signingDate.getTime() <= t);
  const validUntil = w.signingDate.getTime() + w.expiresIn * 1000;
  assert.ok(validUntil - t >= PRESIGN_TTL_SECONDS * 1000, 'valid for at least the TTL from now');
  assert.strictEqual(signingWindow(t + 1000).index, w.index, 'a second later: same window');
});

test('two fetches in the same window get the same signed link; signing uses the window start', async () => {
  const calls = [];
  const original = s3Service.getPresignedGetUrl;
  s3Service.getPresignedGetUrl = async (key, expiresIn, options = {}) => {
    calls.push({ key, expiresIn, signingDate: options.signingDate });
    return `https://${bucket}.s3.${region}.amazonaws.com/${key}?X-Amz-Date=${options.signingDate?.toISOString()}&X-Amz-Expires=${expiresIn}`;
  };
  try {
    const a = await attachPresignedMedia(slide());
    const b = await attachPresignedMedia(slide());
    assert.strictEqual(a.elements.elements[0].content.url, b.elements.elements[0].content.url);
    assert.ok(calls.every((c) => c.signingDate instanceof Date), 'a fixed signing date is passed');
    assert.strictEqual(calls[0].signingDate.getTime(), signingWindow().signingDate.getTime());
  } finally {
    s3Service.getPresignedGetUrl = original;
  }
});

test('real AWS presigner: same key + same signing date → identical URL', async () => {
  const date = signingWindow().signingDate;
  const one = await s3Service.getPresignedGetUrl('w/assets/a.png', 3600, { signingDate: date });
  const two = await s3Service.getPresignedGetUrl('w/assets/a.png', 3600, { signingDate: date });
  assert.strictEqual(one, two);
  const unpinned1 = await s3Service.getPresignedGetUrl('w/assets/a.png', 3600);
  await new Promise((r) => setTimeout(r, 1100));
  const unpinned2 = await s3Service.getPresignedGetUrl('w/assets/a.png', 3600);
  assert.notStrictEqual(unpinned1, unpinned2, 'without a pinned date the link changes (the old behaviour)');
});
