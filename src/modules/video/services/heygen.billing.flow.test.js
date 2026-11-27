'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SRC = path.resolve(__dirname, '../../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const AppError = require(path.join(SRC, 'shared/utils/AppError'));
const { calculateUsageCredits, FEATURE } = require(path.join(SRC, 'shared/config/creditPricing'));

const store = new Map();
const calls = { fetch: 0, upload: [], charges: [], afford: 0 };
const control = {
  refuseAfford: false,
  refuseCharge: false,
  failUpload: false,
  quotaFull: false,
  remote: null,
};

stub('shared/config/prismaClient.js', {
  project: {
    async findFirst() {
      return { id: 'proj-1', folderId: 'folder-1' };
    },
    async findUnique() {
      return { name: 'Project', data: {} };
    },
  },
});
stub('modules/video/heygen.dao.js', {
  async updateHeygenResponse(id, data) {
    const row = store.get(id);
    Object.assign(row, data);
    return { ...row };
  },
});
stub('modules/heygen/heygenV3.service.js', {
  async getVideoStatus() {
    return control.remote;
  },
});
stub('modules/s3/s3.service.js', {
  async uploadFileToKey(_buffer, key) {
    if (control.failUpload) throw new Error('s3 down');
    calls.upload.push(key);
    return { key, url: `https://s3.example/${key}` };
  },
  async getPresignedGetUrl() {
    return 'https://s3.example/presigned';
  },
});
stub('modules/credit/creditLedger.service.js', {
  async assertCanAfford() {
    calls.afford += 1;
    if (control.refuseAfford) throw new AppError('Insufficient credits', 402);
  },
  async chargeUsage(args) {
    if (control.refuseCharge) throw new AppError('Insufficient credits', 402);
    // The real ledger is idempotent on the key; mirror that so a repeat is not a second charge.
    if (calls.charges.some((c) => c.idempotencyKey === args.idempotencyKey)) {
      return { skipped: true, reason: 'idempotent' };
    }
    calls.charges.push(args);
    return { skipped: false, charged: args.amountAc };
  },
});
stub('modules/storage/storageAccounting.service.js', {
  async getWorkspaceOwnerOrThrow() {
    return { id: 'owner-1' };
  },
  async recalculateUserStorageUsed() {},
  async assertOwnerCanFitAdditionalBytes() {
    if (control.quotaFull) throw new AppError('Storage limit reached', 413);
  },
});
stub('modules/project/projectStorage.service.js', {
  async recalculateProjectStorage() {},
});

global.fetch = async () => {
  calls.fetch += 1;
  return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
};

const {
  syncHeygenVideoToS3AndDb,
  copyHeygenVideoToS3,
  resolveHeygenVideoDurationSeconds,
} = require('./heygen.service');

const COMPLETED = {
  status: 'completed',
  video_url: 'https://cdn.example/hg.mp4',
  duration: 10,
  raw: { data: { status: 'completed', duration: 10 } },
};

function seed(extra = {}) {
  const row = {
    id: 'hv-1',
    workspaceId: 'ws-1',
    folderId: 'folder-1',
    projectId: 'proj-1',
    sceneId: 'scene-1',
    videoId: 'hg-1',
    videoUrl: '',
    s3Key: null,
    status: 'processing',
    billingStatus: 'pending',
    creditsCharged: null,
    triggeredByUserId: 'user-1',
    rawResponse: null,
    billingContext: {
      script: 'hello world',
      avatarEngine: 'avatar_iv',
      avatarType: 'studio_avatar',
      resolution: '1080p',
      projectName: 'Project',
      sceneName: 'Scene',
    },
    ...extra,
  };
  store.set(row.id, { ...row });
  return { ...row };
}

function reset() {
  store.clear();
  calls.fetch = 0;
  calls.upload = [];
  calls.charges = [];
  calls.afford = 0;
  control.refuseAfford = false;
  control.refuseCharge = false;
  control.failUpload = false;
  control.quotaFull = false;
  control.remote = COMPLETED;
}

const expectedAc = (seconds) =>
  calculateUsageCredits({
    feature: FEATURE.HEYGEN_VIDEO,
    durationSeconds: seconds,
    avatarEngine: 'avatar_iv',
    avatarType: 'studio_avatar',
    resolution: '1080p',
  }).athenaCredits;

test('normal completion: billed once and stored (unchanged outcome)', async () => {
  reset();
  const result = await syncHeygenVideoToS3AndDb(seed(), { poll: false });
  assert.equal(result.status, 'completed');
  assert.ok(result.s3Key);
  assert.equal(result.billingStatus, 'charged');
  assert.equal(calls.charges.length, 1);
  assert.equal(calls.charges[0].amountAc, expectedAc(10));
  assert.equal(calls.upload.length, 1);
});

test('charge refused: nothing is stored, so the next check bills it instead of giving it away', async () => {
  reset();
  control.refuseCharge = true;
  await assert.rejects(
    () => syncHeygenVideoToS3AndDb(seed(), { poll: false }),
    (err) => err.statusCode === 402
  );
  let row = store.get('hv-1');
  assert.equal(row.s3Key, null, 'no stored copy while unbilled');
  assert.equal(calls.upload.length, 0);
  assert.equal(row.status, 'completed');
  assert.equal(row.billingStatus, 'pending');
  assert.ok(row.videoUrl, 'still plays from the HeyGen URL');

  control.refuseCharge = false;
  const retried = await syncHeygenVideoToS3AndDb({ ...row }, { poll: false });
  assert.ok(retried.s3Key);
  assert.equal(retried.billingStatus, 'charged');
  assert.equal(calls.charges.length, 1, 'billed exactly once');
});

test('cannot afford: refused before the video is even downloaded', async () => {
  reset();
  control.refuseAfford = true;
  await assert.rejects(
    () => syncHeygenVideoToS3AndDb(seed(), { poll: false }),
    (err) => err.statusCode === 402
  );
  assert.equal(calls.fetch, 0, 'no download');
  assert.equal(calls.upload.length, 0);
  assert.equal(calls.charges.length, 0);
  assert.equal(store.get('hv-1').s3Key, null);
});

test('copy without `remote` (download endpoint path) still bills, using the stored duration', async () => {
  reset();
  const row = seed({
    status: 'completed',
    videoUrl: 'https://cdn.example/hg.mp4',
    rawResponse: { data: { status: 'completed', duration: 20 } },
  });
  const result = await copyHeygenVideoToS3(row, null);
  assert.ok(result.s3Key);
  assert.equal(result.billingStatus, 'charged');
  assert.equal(calls.charges.length, 1);
  assert.equal(calls.charges[0].metadata.durationSeconds, 20);
  assert.equal(calls.charges[0].amountAc, expectedAc(20));
});

test('upload fails after the charge: stays billed once and is stored on retry', async () => {
  reset();
  control.failUpload = true;
  await assert.rejects(() => syncHeygenVideoToS3AndDb(seed(), { poll: false }), /s3 down/);
  let row = store.get('hv-1');
  assert.equal(row.billingStatus, 'charged');
  assert.equal(row.s3Key, null);
  assert.equal(calls.charges.length, 1);

  control.failUpload = false;
  const retried = await syncHeygenVideoToS3AndDb({ ...row }, { poll: false });
  assert.ok(retried.s3Key);
  assert.equal(calls.charges.length, 1, 'no second charge');
});

test('storage quota refusal happens before any charge', async () => {
  reset();
  control.quotaFull = true;
  await assert.rejects(
    () => syncHeygenVideoToS3AndDb(seed(), { poll: false }),
    (err) => err.statusCode === 413
  );
  assert.equal(calls.charges.length, 0);
  assert.equal(store.get('hv-1').billingStatus, 'pending');
  assert.equal(calls.upload.length, 0);
});

test('a row with no triggering user is stored and marked skipped, never charged', async () => {
  reset();
  const result = await syncHeygenVideoToS3AndDb(seed({ triggeredByUserId: null }), { poll: false });
  assert.ok(result.s3Key);
  assert.equal(result.billingStatus, 'skipped');
  assert.equal(calls.charges.length, 0);
});

test('rows that already have a stored file are left alone (no retroactive charging)', async () => {
  reset();
  const legacy = seed({ status: 'completed', s3Key: 'old/key.mp4', billingStatus: 'pending' });
  const result = await syncHeygenVideoToS3AndDb(legacy, { poll: false });
  assert.equal(result.s3Key, 'old/key.mp4');
  assert.equal(calls.charges.length, 0);
  assert.equal(calls.fetch, 0);
  assert.equal(calls.afford, 0);
});

test('resolveHeygenVideoDurationSeconds prefers remote, then stored response, then script estimate', () => {
  const base = { billingContext: { script: 'hello world' }, rawResponse: null };
  assert.equal(resolveHeygenVideoDurationSeconds(base, { duration: 12 }), 12);
  assert.equal(
    resolveHeygenVideoDurationSeconds({ ...base, rawResponse: { data: { duration: 30 } } }, null),
    30
  );
  assert.equal(
    resolveHeygenVideoDurationSeconds({ ...base, rawResponse: { duration: 15 } }, { duration: null }),
    15
  );
  assert.equal(resolveHeygenVideoDurationSeconds(base, null), 5, 'estimate has a 5s floor');
});
