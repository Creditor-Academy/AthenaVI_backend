'use strict';

const crypto = require('crypto');
const redisConfig = require('../../../shared/config/redis');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const logger = require('../../../shared/utils/logger');

const LOCK_KEY_PREFIX = 'heygen:video:create:lock:';
const OUTCOME_KEY_PREFIX = 'heygen:video:create:outcome:';
const IDEM_KEY_PREFIX = 'heygen:video:idem:';

const DEFAULT_LOCK_TTL_SEC = 60;
const DEFAULT_OUTCOME_TTL_SEC = 30;
const DEFAULT_IDEM_TTL_SEC = 60;
const DEFAULT_LOCK_WAIT_MS = 15_000;
const DEFAULT_LOCK_POLL_MS = 200;
const DEFAULT_IN_PROGRESS_WAIT_MS = 5_000;
const DEFAULT_IN_PROGRESS_POLL_MS = 250;
const FALLBACK_IDEM_BUCKET_MS = 15_000;

const COMPARE_AND_DEL_LUA = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
`;

/** In-process deduplication keyed by initial requestHash. */
const videoCreateInflight = new Map();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function lockKey(requestHash) {
  return `${LOCK_KEY_PREFIX}${requestHash}`;
}

function outcomeKey(lockToken) {
  return `${OUTCOME_KEY_PREFIX}${lockToken}`;
}

function idemSlotKey(slotHash) {
  return `${IDEM_KEY_PREFIX}${slotHash}`;
}

async function safeCompareAndDelete(key, expectedValue) {
  try {
    if (!redisConfig.isRedisReady()) return;
    const { redisClient } = redisConfig;
    if (typeof redisClient.eval === 'function') {
      await redisClient.eval(COMPARE_AND_DEL_LUA, {
        keys: [key],
        arguments: [String(expectedValue)],
      });
      return;
    }
    const current = await redisClient.get(key);
    if (current === expectedValue) {
      await redisClient.del(key);
    }
  } catch {
    // Best-effort unlock; TTL bounds staleness.
  }
}

async function writeLockOutcome(lockToken, payload, ttlSec = DEFAULT_OUTCOME_TTL_SEC) {
  try {
    if (!redisConfig.isRedisReady()) return;
    await redisConfig.redisClient.set(outcomeKey(lockToken), JSON.stringify(payload), {
      EX: ttlSec,
    });
  } catch {
    // Best-effort outcome publish; waiters also re-check Postgres.
  }
}

async function readLockOutcome(lockToken) {
  if (!lockToken) return null;
  try {
    if (!redisConfig.isRedisReady()) return null;
    const raw = await redisConfig.redisClient.get(outcomeKey(lockToken));
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function resolveOutcomeOrThrow(outcome, { loadRowById, loadReusableByHash }) {
  if (outcome.ok) {
    if (outcome.id && typeof loadRowById === 'function') {
      const byId = await loadRowById(outcome.id);
      if (byId) return byId;
    }
    if (typeof loadReusableByHash === 'function') {
      const byHash = await loadReusableByHash();
      if (byHash) return byHash;
    }
    return null;
  }

  if (outcome.isOperational) {
    throw new AppError(outcome.message || messages.HEYGEN_REQUEST_FAILED, outcome.statusCode || 400);
  }
  throw new AppError(messages.INTERNAL_SERVER_ERROR, 500);
}

async function runAsRedisLockLeader(key, lockToken, fn, { outcomeTtlSec }) {
  try {
    const row = await fn();
    await writeLockOutcome(lockToken, { ok: true, id: row?.id || null }, outcomeTtlSec);
    return row;
  } catch (err) {
    const isOperational = Boolean(err instanceof AppError && err.isOperational);
    await writeLockOutcome(
      lockToken,
      {
        ok: false,
        isOperational,
        statusCode: isOperational ? err.statusCode : 500,
        message: isOperational ? err.message : messages.INTERNAL_SERVER_ERROR,
      },
      outcomeTtlSec
    );
    throw err;
  } finally {
    await safeCompareAndDelete(key, lockToken);
  }
}

/**
 * Coalesces concurrent creates for the same `requestHash`:
 * 1) In-process callers share the same Promise (`videoCreateInflight`).
 * 2) Cross-process callers coordinate via a short-TTL Redis NX lock and per-token outcome key so
 *    even engine-fallback creates (which persist under a different `requestHash`) return the leader's
 *    saved row without making a second `POST /v3/videos` call.
 */
async function withHeygenVideoCreateLock(
  {
    requestHash,
    loadRowById,
    loadReusableByHash,
    skipInProcessMap = false,
    lockTtlSec = DEFAULT_LOCK_TTL_SEC,
    outcomeTtlSec = DEFAULT_OUTCOME_TTL_SEC,
    lockWaitMs = DEFAULT_LOCK_WAIT_MS,
    lockPollMs = DEFAULT_LOCK_POLL_MS,
  },
  fn
) {
  if (!skipInProcessMap) {
    const inflight = videoCreateInflight.get(requestHash);
    if (inflight) {
      return inflight;
    }
  }

  const run = (async () => {
    if (!redisConfig.isRedisReady()) {
      return fn();
    }

    const { redisClient } = redisConfig;
    const key = lockKey(requestHash);
    const myToken = crypto.randomUUID();
    let acquired = false;
    try {
      acquired = (await redisClient.set(key, myToken, { NX: true, EX: lockTtlSec })) === 'OK';
    } catch (err) {
      logger.warn('heygen_video_create_lock_redis_error', {
        error: String(err?.message || err).slice(0, 300),
      });
      return fn();
    }

    if (acquired) {
      return runAsRedisLockLeader(key, myToken, fn, { outcomeTtlSec });
    }

    let holderToken = null;
    try {
      holderToken = await redisClient.get(key);
    } catch (err) {
      logger.warn('heygen_video_create_lock_redis_error', {
        error: String(err?.message || err).slice(0, 300),
      });
      return fn();
    }

    const deadline = Date.now() + lockWaitMs;
    while (Date.now() < deadline) {
      if (holderToken) {
        const outcome = await readLockOutcome(holderToken);
        if (outcome) {
          const resolved = await resolveOutcomeOrThrow(outcome, {
            loadRowById,
            loadReusableByHash,
          });
          if (resolved) return resolved;
        }
      }

      let currentHolder = null;
      try {
        currentHolder = await redisClient.get(key);
      } catch {
        return fn();
      }

      if (!currentHolder) {
        if (holderToken) {
          const finalOutcome = await readLockOutcome(holderToken);
          if (finalOutcome) {
            const resolved = await resolveOutcomeOrThrow(finalOutcome, {
              loadRowById,
              loadReusableByHash,
            });
            if (resolved) return resolved;
          }
        }

        if (typeof loadReusableByHash === 'function') {
          const existing = await loadReusableByHash();
          if (existing) return existing;
        }

        let claimedAfterRelease = false;
        try {
          claimedAfterRelease =
            (await redisClient.set(key, myToken, { NX: true, EX: lockTtlSec })) === 'OK';
        } catch {
          return fn();
        }
        if (claimedAfterRelease) {
          return runAsRedisLockLeader(key, myToken, fn, { outcomeTtlSec });
        }

        try {
          holderToken = await redisClient.get(key);
        } catch {
          return fn();
        }
      } else if (!holderToken) {
        holderToken = currentHolder;
      }

      await sleep(lockPollMs);
    }

    throw new AppError(messages.HEYGEN_VIDEO_CREATE_IN_PROGRESS, 409);
  })();

  if (!skipInProcessMap) {
    videoCreateInflight.set(requestHash, run);
  }

  try {
    return await run;
  } finally {
    if (!skipInProcessMap && videoCreateInflight.get(requestHash) === run) {
      videoCreateInflight.delete(requestHash);
    }
  }
}

function computeAttemptSlotHash({ attemptHash, retryRow, jsonBody }) {
  return sha256Hex(
    JSON.stringify({
      attemptHash,
      priorVideoId: retryRow?.videoId || null,
      jsonBody,
    })
  );
}

function buildFallbackIdempotencyKey(slotHash, nowMs = Date.now(), bucketMs = FALLBACK_IDEM_BUCKET_MS) {
  const bucket = Math.floor(nowMs / bucketMs);
  const digest = sha256Hex(JSON.stringify({ slotHash, bucket }));
  return `hv-${digest}`;
}

function isHeygenRequestInProgressError(err) {
  if (!(err instanceof AppError) || err.statusCode !== 409) {
    return false;
  }
  if (err.heygenErrorCode === 'request_in_progress') {
    return true;
  }
  const msg = String(err.message || '');
  return /idempotency-key.*in progress|request_in_progress/i.test(msg);
}

/**
 * Sends a safe per-attempt `Idempotency-Key` on `POST /v3/videos`:
 * - Scoped by `(attemptHash, retryRow.videoId, jsonBody)` so concurrent retries share one key, while
 *   a later retry after a failed video (`retryRow.videoId` changed) or an engine fallback
 *   (`attemptHash` changed) gets a distinct key.
 * - When Redis is available, stores a random UUID for 60s and deletes it immediately on any
 *   non-`request_in_progress` error so transient 4xx/5xx failures never replay for 24h on HeyGen.
 * - When Redis is unavailable, falls back to a 15-second bucketed deterministic key.
 * - If HeyGen responds `409 request_in_progress`, polls `findExisting` briefly so a racing caller
 *   returns the winner's persisted row instead of surfacing an error.
 */
async function runHeygenCreateAttempt({
  attemptHash,
  retryRow,
  jsonBody,
  execute,
  findExisting,
  idemTtlSec = DEFAULT_IDEM_TTL_SEC,
  inProgressWaitMs = DEFAULT_IN_PROGRESS_WAIT_MS,
  inProgressPollMs = DEFAULT_IN_PROGRESS_POLL_MS,
  nowMs = Date.now,
}) {
  const slotHash = computeAttemptSlotHash({ attemptHash, retryRow, jsonBody });
  const redisKey = idemSlotKey(slotHash);

  let idempotencyKey = null;
  let ownedCandidate = null;

  if (redisConfig.isRedisReady()) {
    const { redisClient } = redisConfig;
    const candidate = `hv-${crypto.randomUUID()}`;
    try {
      const setRes = await redisClient.set(redisKey, candidate, { NX: true, EX: idemTtlSec });
      if (setRes === 'OK') {
        idempotencyKey = candidate;
        ownedCandidate = candidate;
      } else {
        idempotencyKey = (await redisClient.get(redisKey)) || candidate;
      }
    } catch {
      idempotencyKey = buildFallbackIdempotencyKey(slotHash, nowMs());
    }
  } else {
    idempotencyKey = buildFallbackIdempotencyKey(slotHash, nowMs());
  }

  try {
    const created = await execute(idempotencyKey);
    return { created, replayedExisting: null };
  } catch (err) {
    if (isHeygenRequestInProgressError(err)) {
      if (typeof findExisting === 'function') {
        const deadline = Date.now() + inProgressWaitMs;
        while (Date.now() < deadline) {
          const existing = await findExisting();
          if (existing) {
            return { created: null, replayedExisting: existing };
          }
          await sleep(inProgressPollMs);
        }
      }
      throw new AppError(messages.HEYGEN_VIDEO_CREATE_IN_PROGRESS, 409);
    }

    if (ownedCandidate) {
      await safeCompareAndDelete(redisKey, ownedCandidate);
    }
    throw err;
  }
}

module.exports = {
  withHeygenVideoCreateLock,
  runHeygenCreateAttempt,
  isHeygenRequestInProgressError,
  buildFallbackIdempotencyKey,
  computeAttemptSlotHash,
};
