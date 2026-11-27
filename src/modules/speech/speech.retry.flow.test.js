'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SRC = path.resolve(__dirname, '../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const AppError = require(path.join(SRC, 'shared/utils/AppError'));
const { generateSpeechRequestHash } = require(path.join(SRC, 'shared/utils/requestHash'));

const rows = new Map();
const calls = { save: 0, claim: 0, heygen: 0, upload: [], deleted: [], charges: [] };
const ledger = { refuse: false };

stub('shared/config/prismaClient.js', {
  project: {
    async findFirst() {
      return { id: 'proj-1', folderId: 'folder-1', name: 'Project', data: {} };
    },
    async findUnique() {
      return { name: 'Project', data: {} };
    },
  },
});
stub('modules/speech/speech.dao.js', {
  async findSpeechGenerationByRequestHash(hash) {
    return [...rows.values()].find((r) => r.requestHash === hash) || null;
  },
  async saveSpeechGeneration(data) {
    calls.save += 1;
    const row = {
      id: `sp-${rows.size + 1}`,
      audioUrl: '',
      s3Key: null,
      billingStatus: 'pending',
      creditsCharged: null,
      ...data,
    };
    rows.set(row.id, row);
    return { ...row };
  },
  async claimFailedSpeechGeneration(id, data) {
    calls.claim += 1;
    const row = rows.get(id);
    if (!row || row.status !== 'failed' || row.billingStatus === 'charged') return null;
    Object.assign(row, data, {
      status: 'processing',
      billingStatus: 'pending',
      s3Key: null,
      audioUrl: '',
      creditsCharged: null,
    });
    return { ...row };
  },
  async updateSpeechGeneration(id, data) {
    const row = rows.get(id);
    Object.assign(row, data);
    return { ...row };
  },
  async findSpeechGenerationByIdForProject(id) {
    const row = rows.get(id);
    return row ? { ...row } : null;
  },
});
stub('modules/heygen/heygenV3.service.js', {
  async assertVoiceSupportsStarfishSpeech() {},
  async generateSpeechPreview() {
    calls.heygen += 1;
    return { data: { audio_url: 'https://cdn.example/a.mp3', duration: 3 } };
  },
});
stub('modules/s3/s3.service.js', {
  async uploadFileToKey(_buffer, key) {
    calls.upload.push(key);
    return { key, url: `https://s3.example/${key}` };
  },
  async getPresignedGetUrl() {
    return 'https://s3.example/presigned';
  },
  async deleteFile(key) {
    calls.deleted.push(key);
  },
});
stub('shared/utils/downloadRemote.js', {
  async downloadRemote() {
    return Buffer.alloc(16);
  },
});
stub('modules/project/projectStorage.service.js', {
  async recalculateProjectStorage() {},
});
stub('modules/credit/creditLedger.service.js', {
  async assertCanAfford() {},
  async chargeUsage(args) {
    if (ledger.refuse) throw new AppError('Insufficient credits', 402);
    calls.charges.push(args);
    return { charged: args.amountAc };
  },
});

const { generateProjectSpeech } = require('./speech.service');

const input = {
  userId: 'user-1',
  workspaceId: 'ws-1',
  projectId: 'proj-1',
  sceneId: 'scene-1',
  voiceId: 'voice-1',
  script: 'Hello there, this is a test narration.',
};

function hashFor() {
  return generateSpeechRequestHash({
    workspaceId: input.workspaceId,
    projectId: input.projectId,
    sceneId: input.sceneId,
    voiceId: input.voiceId,
    script: input.script,
    speed: 1,
    inputType: 'text',
    locale: null,
  });
}

function reset() {
  rows.clear();
  calls.save = 0;
  calls.claim = 0;
  calls.heygen = 0;
  calls.upload = [];
  calls.deleted = [];
  calls.charges = [];
  ledger.refuse = false;
}

test('first request creates a row, generates, and charges once (unchanged behaviour)', async () => {
  reset();
  const result = await generateProjectSpeech(input);
  assert.equal(calls.save, 1);
  assert.equal(calls.claim, 0);
  assert.equal(calls.heygen, 1);
  assert.equal(result.status, 'completed');
  assert.equal(result.billingStatus, 'charged');
  assert.ok(result.s3Key);
  assert.equal(calls.charges.length, 1);
  assert.equal(calls.deleted.length, 0);
});

test('a completed row is returned as-is with no new work (idempotent)', async () => {
  reset();
  await generateProjectSpeech(input);
  const heygenBefore = calls.heygen;
  const again = await generateProjectSpeech(input);
  assert.equal(again.status, 'completed');
  assert.equal(calls.heygen, heygenBefore);
  assert.equal(calls.save, 1);
  assert.equal(calls.claim, 0);
  assert.equal(calls.charges.length, 1);
});

test('charge refused: uploaded audio is deleted and the failed row no longer points at it', async () => {
  reset();
  ledger.refuse = true;
  await assert.rejects(() => generateProjectSpeech(input), (err) => err.statusCode === 402);

  assert.equal(calls.upload.length, 1);
  assert.deepEqual(calls.deleted, calls.upload);
  const [row] = [...rows.values()];
  assert.equal(row.status, 'failed');
  assert.equal(row.billingStatus, 'failed');
  assert.equal(row.s3Key, null);
  assert.equal(row.audioUrl, '');
});

test('failed unbilled narration is retried on the same row and can then succeed', async () => {
  reset();
  ledger.refuse = true;
  await assert.rejects(() => generateProjectSpeech(input));
  const [failedRow] = [...rows.values()];
  const failedId = failedRow.id;

  ledger.refuse = false;
  const retried = await generateProjectSpeech(input);

  assert.equal(calls.save, 1, 'no second row');
  assert.equal(calls.claim, 1);
  assert.equal(retried.id, failedId);
  assert.equal(retried.status, 'completed');
  assert.equal(retried.billingStatus, 'charged');
  assert.equal(calls.charges.length, 1, 'billed exactly once');
  assert.equal(rows.size, 1);
});

test('a failed row that was already billed is never retried', async () => {
  reset();
  rows.set('sp-billed', {
    id: 'sp-billed',
    requestHash: hashFor(),
    status: 'failed',
    billingStatus: 'charged',
    s3Key: null,
  });
  const result = await generateProjectSpeech(input);
  assert.equal(result.id, 'sp-billed');
  assert.equal(calls.claim, 0);
  assert.equal(calls.heygen, 0);
  assert.equal(calls.charges.length, 0);
});

test('when another request claims the failed row first, its result is returned', async () => {
  reset();
  rows.set('sp-race', {
    id: 'sp-race',
    requestHash: hashFor(),
    status: 'failed',
    billingStatus: 'failed',
    s3Key: null,
  });
  // Simulate losing the claim: the row is already being processed by the time we claim it.
  const dao = require(path.join(SRC, 'modules/speech/speech.dao.js'));
  const realClaim = dao.claimFailedSpeechGeneration;
  dao.claimFailedSpeechGeneration = async () => {
    rows.get('sp-race').status = 'processing';
    return null;
  };
  try {
    const result = await generateProjectSpeech(input);
    assert.equal(result.id, 'sp-race');
    assert.equal(result.status, 'processing');
    assert.equal(calls.heygen, 0);
    assert.equal(calls.charges.length, 0);
  } finally {
    dao.claimFailedSpeechGeneration = realClaim;
  }
});
