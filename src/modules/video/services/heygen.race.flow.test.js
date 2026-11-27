'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SRC = path.resolve(__dirname, '../../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const AppError = require(path.join(SRC, 'shared/utils/AppError'));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const redisStore = new Map();
const control = {
  redisReady: false,
  createDelayMs: 30,
  createHandler: null,
  lookBody: null,
  forceP2002Once: false,
};
const rowsById = new Map();
const rowsByHash = new Map();
const createCalls = [];
let nextRowSeq = 1;
let nextVideoSeq = 1;

const fakeRedisClient = {
  async get(key) {
    return redisStore.has(key) ? redisStore.get(key) : null;
  },
  async set(key, value, opts = {}) {
    if (opts.NX && redisStore.has(key)) return null;
    redisStore.set(key, String(value));
    return 'OK';
  },
  async del(keyOrKeys) {
    const keys = Array.isArray(keyOrKeys) ? keyOrKeys : [keyOrKeys];
    let removed = 0;
    for (const k of keys) {
      if (redisStore.delete(k)) removed += 1;
    }
    return removed;
  },
  async eval(_script, { keys, arguments: args }) {
    const cur = redisStore.get(keys[0]);
    if (cur === args[0]) {
      redisStore.delete(keys[0]);
      return 1;
    }
    return 0;
  },
};

stub('shared/config/redis.js', {
  redisClient: fakeRedisClient,
  isRedisReady: () => control.redisReady,
  isRedisOptional: () => true,
  connectRedis: async () => control.redisReady,
  assertRedisReady: () => {},
});

stub('shared/config/prismaClient.js', {
  project: {
    async findFirst({ where }) {
      return { id: where.id, folderId: 'folder-1' };
    },
    async findUnique() {
      return { name: 'Demo Project', data: {} };
    },
  },
});

stub('modules/video/heygen.dao.js', {
  async findHeygenResponseByRequestHash(requestHash) {
    const row = rowsByHash.get(requestHash);
    return row ? { ...row } : null;
  },
  async findHeygenResponseByIdForProject(id, workspaceId, projectId) {
    const row = rowsById.get(id);
    if (!row || row.workspaceId !== workspaceId || row.projectId !== projectId) return null;
    return { ...row };
  },
  async saveHeygenResponse(data) {
    if (control.forceP2002Once) {
      control.forceP2002Once = false;
      const raced = rowsByHash.get(data.requestHash);
      if (raced) {
        const err = new Error('Unique constraint failed on requestHash');
        err.code = 'P2002';
        throw err;
      }
    }
    if (rowsByHash.has(data.requestHash)) {
      const err = new Error('Unique constraint failed on requestHash');
      err.code = 'P2002';
      throw err;
    }
    const id = `row-${nextRowSeq++}`;
    const row = {
      id,
      billingStatus: 'pending',
      creditsCharged: null,
      ...data,
    };
    rowsById.set(id, row);
    rowsByHash.set(row.requestHash, row);
    return { ...row };
  },
  async reuseFailedHeygenResponse(id, data) {
    const existing = rowsById.get(id);
    if (
      !existing ||
      existing.status !== 'failed' ||
      existing.s3Key != null ||
      existing.billingStatus === 'charged'
    ) {
      return { count: 0, row: existing ? { ...existing } : null };
    }
    const updated = {
      ...existing,
      ...data,
      videoUrl: '',
      s3Key: null,
      fileSizeBytes: null,
      billingStatus: 'pending',
      creditsCharged: null,
      billedDurationSec: null,
    };
    rowsById.set(id, updated);
    rowsByHash.set(updated.requestHash, updated);
    return { count: 1, row: { ...updated } };
  },
  async updateHeygenResponse(id, data) {
    const row = rowsById.get(id);
    Object.assign(row, data);
    rowsByHash.set(row.requestHash, row);
    return { ...row };
  },
});

stub('modules/heygen/heygenV3.service.js', {
  async getAvatarLook() {
    if (control.lookBody) return control.lookBody;
    return { data: { id: 'look-1', supported_api_engines: ['avatar_iv'] } };
  },
  async getVideoVoiceCapabilities() {
    return { data: { capabilities: [] } };
  },
  async createVideo(jsonBody, options = {}) {
    createCalls.push({ jsonBody, options });
    if (control.createDelayMs > 0) {
      await sleep(control.createDelayMs);
    }
    if (typeof control.createHandler === 'function') {
      return control.createHandler(jsonBody, options, createCalls.length);
    }
    const videoId = `vid-${nextVideoSeq++}`;
    return {
      videoId,
      status: 'processing',
      raw: { data: { video_id: videoId, status: 'processing' } },
      apiVersion: 'v3',
    };
  },
});

stub('modules/credit/creditLedger.service.js', {
  async assertCanAfford() {},
  async chargeUsage() {},
});

stub('modules/heygen/heygenAccess.service.js', {
  async assertCanUseAvatarLook() {},
  async assertCanUseVoice() {},
});

stub('modules/s3/s3.service.js', {
  async uploadFileToKey() {},
  async getPresignedGetUrl() {},
});

stub('modules/storage/storageAccounting.service.js', {
  async assertOwnerCanFitAdditionalBytes() {},
});

stub('shared/utils/logger.js', {
  info() {},
  warn() {},
  error() {},
});

const {
  generateAvatarVideo,
  persistHeygenResponse,
} = require('./heygen.service');
const {
  withHeygenVideoCreateLock,
  runHeygenCreateAttempt,
} = require('./heygenCreateCoordinator');

const BASE_INPUT = {
  userId: 'user-1',
  workspaceId: 'ws-1',
  projectId: 'proj-1',
  sceneId: 'scene-1',
  avatarId: 'look-1',
  avatarEngine: 'avatar_iv',
  avatarType: 'photo_avatar',
  title: 'Intro',
  resolution: '1080p',
  aspectRatio: '16:9',
  backgroundColor: '#ffffff',
  voiceId: 'voice-1',
  script: 'Welcome to Athena virtual instructor.',
  outputFormat: 'mp4',
};

function resetState() {
  redisStore.clear();
  rowsById.clear();
  rowsByHash.clear();
  createCalls.length = 0;
  control.redisReady = false;
  control.createDelayMs = 30;
  control.createHandler = null;
  control.lookBody = null;
  control.forceP2002Once = false;
  nextRowSeq = 1;
  nextVideoSeq = 1;
}

describe('HeyGen video create & retry race protection', () => {
  beforeEach(() => {
    resetState();
  });

  it('coalesces two simultaneous first-time creates into a single HeyGen job', async () => {
    const [r1, r2] = await Promise.all([
      generateAvatarVideo(BASE_INPUT),
      generateAvatarVideo(BASE_INPUT),
    ]);

    assert.equal(createCalls.length, 1, 'HeyGen POST /v3/videos called once');
    assert.match(
      createCalls[0].options.idempotencyKey,
      /^[A-Za-z0-9_\-:.]{1,255}$/,
      'sends a valid HeyGen Idempotency-Key'
    );
    assert.equal(r1.id, r2.id);
    assert.equal(r1.videoId, 'vid-1');
    assert.equal(rowsById.size, 1);
  });

  it('coalesces two simultaneous retries of a failed video into a single HeyGen job', async () => {
    const initial = await generateAvatarVideo(BASE_INPUT);
    assert.equal(initial.videoId, 'vid-1');

    // Simulate the first HeyGen job failing before billing or S3 upload.
    const stored = rowsById.get(initial.id);
    stored.status = 'failed';
    stored.billingStatus = 'failed';
    rowsByHash.set(stored.requestHash, stored);

    const [retryA, retryB] = await Promise.all([
      generateAvatarVideo(BASE_INPUT),
      generateAvatarVideo(BASE_INPUT),
    ]);

    assert.equal(createCalls.length, 2, 'only one new HeyGen job started for both simultaneous retries');
    assert.equal(retryA.id, initial.id, 'reuses the original HeygenResponse row id');
    assert.equal(retryB.id, initial.id);
    assert.equal(retryA.videoId, 'vid-2');
    assert.equal(retryB.videoId, 'vid-2');
    assert.notEqual(
      createCalls[1].options.idempotencyKey,
      createCalls[0].options.idempotencyKey,
      'retry uses a fresh Idempotency-Key distinct from the prior failed videoId'
    );
  });

  it('clears the Redis Idempotency-Key on synchronous POST /v3/videos failure so immediate retry uses a fresh key', async () => {
    control.redisReady = true;
    let attemptNum = 0;
    control.createHandler = async () => {
      attemptNum += 1;
      if (attemptNum === 1) {
        throw new AppError('Too many requests', 429);
      }
      return {
        videoId: 'vid-after-429',
        status: 'processing',
        raw: { data: { video_id: 'vid-after-429', status: 'processing' } },
        apiVersion: 'v3',
      };
    };

    await assert.rejects(() => generateAvatarVideo(BASE_INPUT), (err) => err.statusCode === 429);

    const recovered = await generateAvatarVideo(BASE_INPUT);
    assert.equal(recovered.videoId, 'vid-after-429');
    assert.equal(createCalls.length, 2);
    assert.notEqual(
      createCalls[1].options.idempotencyKey,
      createCalls[0].options.idempotencyKey,
      'failed synchronous call released its Redis idempotency slot'
    );
  });

  it('coalesces concurrent callers across Avatar 6 plan-gate fallback with distinct per-engine keys', async () => {
    control.redisReady = true;
    control.createHandler = async (jsonBody) => {
      if (jsonBody.engine?.type === 'avatar_iv') {
        throw new AppError('This avatar is available only with Avatar 6 Pro or Turbo', 403);
      }
      return {
        videoId: 'vid-a6-1',
        status: 'processing',
        raw: { data: { video_id: 'vid-a6-1', status: 'processing' } },
        apiVersion: 'v3',
      };
    };

    const [a, b] = await Promise.all([
      generateAvatarVideo(BASE_INPUT),
      generateAvatarVideo(BASE_INPUT),
    ]);

    assert.equal(createCalls.length, 2, '1 failed avatar_iv probe + 1 Avatar 6 Turbo create');
    assert.equal(createCalls[0].jsonBody.engine.type, 'avatar_iv');
    assert.equal(createCalls[1].jsonBody.engine.type, 'heygen-avatar-6-turbo');
    assert.notEqual(
      createCalls[0].options.idempotencyKey,
      createCalls[1].options.idempotencyKey,
      'fallback engine gets its own Idempotency-Key'
    );
    assert.equal(a.id, b.id);
    assert.equal(a.videoId, 'vid-a6-1');
  });

  it('coordinates cross-instance callers via Redis lock + outcome key (including fallback rows and errors)', async () => {
    control.redisReady = true;
    let leaderRuns = 0;

    // Simulate two separate Node processes (`skipInProcessMap: true`) where leader saves under a fallback hash.
    const savedRow = { id: 'row-fallback', videoId: 'vid-cross', status: 'processing' };
    const [resA, resB] = await Promise.all([
      withHeygenVideoCreateLock(
        {
          requestHash: 'hash-iv',
          skipInProcessMap: true,
          lockPollMs: 15,
          loadRowById: async (id) => (id === savedRow.id ? savedRow : null),
          loadReusableByHash: async () => null,
        },
        async () => {
          leaderRuns += 1;
          await sleep(40);
          return savedRow;
        }
      ),
      (async () => {
        await sleep(5);
        return withHeygenVideoCreateLock(
          {
            requestHash: 'hash-iv',
            skipInProcessMap: true,
            lockPollMs: 15,
            loadRowById: async (id) => (id === savedRow.id ? savedRow : null),
            loadReusableByHash: async () => null,
          },
          async () => {
            leaderRuns += 1;
            return { id: 'should-not-run' };
          }
        );
      })(),
    ]);

    assert.equal(leaderRuns, 1, 'second instance waited on Redis lock and did not run leader fn');
    assert.deepEqual(resA, savedRow);
    assert.deepEqual(resB, savedRow);

    // Now verify operational error propagation to concurrent waiter, while a later call runs fresh.
    let errLeaderRuns = 0;
    const [errA, errB] = await Promise.allSettled([
      withHeygenVideoCreateLock(
        {
          requestHash: 'hash-err',
          skipInProcessMap: true,
          lockPollMs: 15,
          loadRowById: async () => null,
          loadReusableByHash: async () => null,
        },
        async () => {
          errLeaderRuns += 1;
          await sleep(40);
          throw new AppError('Rate limit exceeded', 429);
        }
      ),
      (async () => {
        await sleep(5);
        return withHeygenVideoCreateLock(
          {
            requestHash: 'hash-err',
            skipInProcessMap: true,
            lockPollMs: 15,
            loadRowById: async () => null,
            loadReusableByHash: async () => null,
          },
          async () => {
            errLeaderRuns += 1;
            return { id: 'unexpected' };
          }
        );
      })(),
    ]);

    assert.equal(errLeaderRuns, 1, 'concurrent follower did not hammer HeyGen a second time');
    assert.equal(errA.status, 'rejected');
    assert.equal(errA.reason.statusCode, 429);
    assert.equal(errB.status, 'rejected');
    assert.equal(errB.reason.statusCode, 429);

    // Subsequent request arriving AFTER unlock runs fresh.
    const freshAfterUnlock = await withHeygenVideoCreateLock(
      {
        requestHash: 'hash-err',
        skipInProcessMap: true,
        lockPollMs: 15,
        loadRowById: async () => null,
        loadReusableByHash: async () => null,
      },
      async () => ({ id: 'fresh-ok' })
    );
    assert.deepEqual(freshAfterUnlock, { id: 'fresh-ok' });
  });

  it('recovers from HeyGen 409 request_in_progress and Prisma P2002 when Redis is unavailable', async () => {
    control.redisReady = false;

    // 1) HeyGen 409 request_in_progress polls Postgres and returns the winning instance's row.
    let winnerRow = null;
    setTimeout(() => {
      winnerRow = { id: 'row-winner', videoId: 'vid-winner', status: 'processing' };
    }, 30);

    const attempt = await runHeygenCreateAttempt({
      attemptHash: 'hash-degraded',
      retryRow: null,
      jsonBody: { script: 'hello' },
      inProgressWaitMs: 500,
      inProgressPollMs: 15,
      execute: async () => {
        const err = new AppError(
          'A request with this Idempotency-Key is already in progress. Retry shortly.',
          409
        );
        err.heygenErrorCode = 'request_in_progress';
        throw err;
      },
      findExisting: async () => winnerRow,
    });
    assert.equal(attempt.created, null);
    assert.deepEqual(attempt.replayedExisting, winnerRow);

    // 2) Prisma P2002 on saveHeygenResponse returns the winning row instead of 500.
    const winnerSaved = await persistHeygenResponse(
      {
        workspaceId: 'ws-1',
        folderId: 'folder-1',
        projectId: 'proj-1',
        sceneId: 'scene-p2002',
        videoId: 'vid-first',
        requestHash: 'hash-p2002',
        status: 'processing',
      },
      null
    );
    const duplicateResolved = await persistHeygenResponse(
      {
        workspaceId: 'ws-1',
        folderId: 'folder-1',
        projectId: 'proj-1',
        sceneId: 'scene-p2002',
        videoId: 'vid-first',
        requestHash: 'hash-p2002',
        status: 'processing',
      },
      null
    );
    assert.equal(duplicateResolved.id, winnerSaved.id);
    assert.equal(duplicateResolved.videoId, 'vid-first');
  });
});
