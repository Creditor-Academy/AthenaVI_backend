'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const heygenDao = require('../heygen.dao');
const {
  isRetryableFailedHeygenRow,
  findReusableOrRetryableResponse,
  persistHeygenResponse,
} = require('./heygen.service');

describe('isRetryableFailedHeygenRow', () => {
  const failed = { status: 'failed', s3Key: null, billingStatus: 'failed', creditsCharged: null };

  it('retries a failed, unbilled row with no stored file', () => {
    assert.equal(isRetryableFailedHeygenRow(failed), true);
    assert.equal(isRetryableFailedHeygenRow({ ...failed, billingStatus: 'pending' }), true);
    assert.equal(isRetryableFailedHeygenRow({ ...failed, creditsCharged: 0 }), true);
  });

  it('never retries rows that are in progress or completed', () => {
    assert.equal(isRetryableFailedHeygenRow({ ...failed, status: 'processing' }), false);
    assert.equal(isRetryableFailedHeygenRow({ ...failed, status: 'pending' }), false);
    assert.equal(isRetryableFailedHeygenRow({ ...failed, status: 'completed' }), false);
  });

  it('never retries a row that was billed or has a stored file', () => {
    assert.equal(isRetryableFailedHeygenRow({ ...failed, billingStatus: 'charged' }), false);
    assert.equal(isRetryableFailedHeygenRow({ ...failed, creditsCharged: 12 }), false);
    assert.equal(isRetryableFailedHeygenRow({ ...failed, s3Key: 'some/key.mp4' }), false);
  });

  it('is false for a missing row', () => {
    assert.equal(isRetryableFailedHeygenRow(null), false);
    assert.equal(isRetryableFailedHeygenRow(undefined), false);
  });
});

describe('failed video retry persistence', () => {
  const original = {
    find: heygenDao.findHeygenResponseByRequestHash,
    save: heygenDao.saveHeygenResponse,
    reuse: heygenDao.reuseFailedHeygenResponse,
  };
  let calls;

  beforeEach(() => {
    calls = { save: [], reuse: [] };
    heygenDao.saveHeygenResponse = async (data) => {
      calls.save.push(data);
      return { id: 'new-row', ...data };
    };
    heygenDao.reuseFailedHeygenResponse = async (id, data) => {
      calls.reuse.push({ id, data });
      return { count: 1, row: { id, ...data } };
    };
  });

  afterEach(() => {
    heygenDao.findHeygenResponseByRequestHash = original.find;
    heygenDao.saveHeygenResponse = original.save;
    heygenDao.reuseFailedHeygenResponse = original.reuse;
  });

  it('returns a completed or processing row untouched (idempotent)', async () => {
    for (const status of ['completed', 'processing']) {
      const row = { id: `row-${status}`, status, s3Key: null, billingStatus: 'pending' };
      heygenDao.findHeygenResponseByRequestHash = async () => row;
      const found = await findReusableOrRetryableResponse('hash');
      assert.equal(found.existing, row);
      assert.equal(found.retryRow, null);
    }
  });

  it('hands back a failed unbilled row as a retry candidate, not as the answer', async () => {
    const row = { id: 'row-failed', status: 'failed', s3Key: null, billingStatus: 'failed' };
    heygenDao.findHeygenResponseByRequestHash = async () => row;
    const found = await findReusableOrRetryableResponse('hash');
    assert.equal(found.existing, null);
    assert.equal(found.retryRow, row);
  });

  it('keeps a billed failed row as the answer', async () => {
    const row = { id: 'row-billed', status: 'failed', s3Key: null, billingStatus: 'charged' };
    heygenDao.findHeygenResponseByRequestHash = async () => row;
    const found = await findReusableOrRetryableResponse('hash');
    assert.equal(found.existing, row);
    assert.equal(found.retryRow, null);
  });

  it('reports no row when the hash is new', async () => {
    heygenDao.findHeygenResponseByRequestHash = async () => null;
    assert.deepEqual(await findReusableOrRetryableResponse('hash'), { existing: null, retryRow: null });
  });

  it('creates a new row for a first request and reuses the row id for a retry', async () => {
    const data = { videoId: 'v2', status: 'processing', requestHash: 'hash' };

    const created = await persistHeygenResponse(data, null);
    assert.equal(created.id, 'new-row');
    assert.equal(calls.save.length, 1);
    assert.equal(calls.reuse.length, 0);

    const reused = await persistHeygenResponse(data, { id: 'row-failed' });
    assert.equal(reused.id, 'row-failed');
    assert.equal(reused.videoId, 'v2');
    assert.equal(calls.save.length, 1, 'no second insert for a retry');
    assert.equal(calls.reuse.length, 1);
  });
});
