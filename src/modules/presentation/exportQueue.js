/**
 * The presentation export queue.
 *
 * With Redis: a BullMQ queue, `presentation-export`. The API adds a job (job id = export id);
 * a worker in this service runs PPT_EXPORT_CONCURRENCY jobs at once (default 2). Jobs survive a
 * restart: a job whose server died is picked up again once (BullMQ "stalled" jobs).
 * PPT_EXPORT_WORKER=0 runs no worker on this instance (an API-only instance, for a separate
 * worker service later).
 *
 * Without Redis (local development, or Redis down at boot), or with PPT_EXPORT_QUEUE=local,
 * jobs run in this process as before. A job that can't be added to Redis also runs here.
 *
 * The export row in the database stays the source of truth for status; the queue holds the
 * work, its progress and the "is it still waiting / running" answer.
 */

const logger = require('../../shared/utils/logger');

const QUEUE_NAME = 'presentation-export';
const START_TIMEOUT_MS = 10_000;

const envNumber = (name, fallback) => (Number(process.env[name]) > 0 ? Number(process.env[name]) : fallback);

/** Redis connection errors repeat on every reconnect attempt: log each kind once per 15s. */
const lastLoggedAt = new Map();
function warnThrottled(event, err) {
  const now = Date.now();
  if (now - (lastLoggedAt.get(event) || 0) < 15_000) return;
  lastLoggedAt.set(event, now);
  logger.warn(event, { error: String(err?.message || err).slice(0, 300) });
}

/** Runs one export: `(data, { signal, onProgress }) => Promise<outcome>`. Set by export.service. */
let processor = null;
/** Called with `(data, error)` when BullMQ fails a job (see the worker's 'failed' event). */
let onJobLost = null;
/** Jobs running in this process: export id → AbortController (Cancel aborts it). */
const running = new Map();
/** Latest progress of jobs running in this process. */
const progressById = new Map();
/** Local jobs added but not started yet. */
const waitingLocal = new Set();

let mode = 'local';
let bull = null; // { queue, worker, connections }

function setProcessor(fn) {
  processor = fn;
}

/**
 * `fn(data, error)` runs when BullMQ gives up on a job: its server died twice ("stalled more
 * than allowable limit"), or the processor threw. The row would otherwise stay in progress with
 * nobody running it.
 */
function setOnJobLost(fn) {
  onJobLost = fn;
}

function concurrency() {
  return envNumber('PPT_EXPORT_CONCURRENCY', 2);
}

function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      timer.unref?.();
    }),
  ]).finally(() => clearTimeout(timer));
}

/** Run a job here, tracking its abort controller and progress. */
async function runHere(exportId, data, onProgress) {
  if (!processor) throw new Error('Export queue has no processor');
  const controller = new AbortController();
  running.set(exportId, controller);
  try {
    return await processor(data, {
      signal: controller.signal,
      onProgress: (progress) => {
        progressById.set(exportId, progress);
        if (onProgress) onProgress(progress);
      },
    });
  } finally {
    running.delete(exportId);
    progressById.delete(exportId);
  }
}

function runLocally(data) {
  const exportId = data.exportId;
  waitingLocal.add(exportId);
  setImmediate(() => {
    waitingLocal.delete(exportId);
    runHere(exportId, data).catch((err) => {
      logger.error('presentation_export_job_crashed', { exportId, error: String(err?.message || err), stack: err?.stack });
      if (onJobLost) Promise.resolve().then(() => onJobLost(data, err)).catch(() => {});
    });
  });
}

/**
 * Connect to Redis and start the queue (and this instance's worker). Falls back to running
 * exports in-process when Redis isn't configured or can't be reached. Safe to call twice.
 * `deps` lets tests pass a stand-in for BullMQ / ioredis.
 */
let starting = null;
function start(deps = {}) {
  if (!starting) starting = startQueue(deps);
  return starting;
}

async function startQueue({ bullmq = null, IORedis = null } = {}) {
  const wanted = String(process.env.PPT_EXPORT_QUEUE || 'auto').toLowerCase();
  const redisUrl = String(process.env.REDIS_URL || '').trim();
  if (wanted === 'local' || (!redisUrl && !bullmq)) {
    mode = 'local';
    logger.info('export_queue_ready', { mode, concurrency: concurrency() });
    return mode;
  }

  const { Queue, Worker } = bullmq || require('bullmq');
  const Redis = IORedis || require('ioredis');
  const connections = [];
  const connect = (opts) => {
    const conn = new Redis(redisUrl, { maxRetriesPerRequest: null, ...opts });
    conn.on?.('error', () => {}); // ioredis logs reconnects itself; BullMQ reports real failures
    connections.push(conn);
    return conn;
  };

  try {
    // A producer connection that fails fast: when Redis is down, adding a job errors at once
    // (and the export runs here) instead of waiting in an offline queue and running twice later.
    const queue = new Queue(QUEUE_NAME, {
      connection: connect({ enableOfflineQueue: false }),
      defaultJobOptions: {
        // Crashes are retried inside the job (export.service runExportJob), so BullMQ runs it once.
        attempts: 1,
        removeOnComplete: { age: 60 * 60, count: 1000 },
        removeOnFail: { age: 24 * 60 * 60, count: 1000 },
      },
    });
    queue.on?.('error', (err) => warnThrottled('export_queue_error', err));
    await withTimeout(queue.waitUntilReady(), START_TIMEOUT_MS, 'Export queue connection');

    let worker = null;
    if (process.env.PPT_EXPORT_WORKER !== '0') {
      worker = new Worker(
        QUEUE_NAME,
        (job) =>
          runHere(job.id, job.data, (progress) => {
            Promise.resolve(job.updateProgress(progress)).catch(() => {});
          }),
        {
          connection: connect({}),
          concurrency: concurrency(),
          // PPTX writing can hold the event loop for a few seconds; don't call that a dead worker.
          lockDuration: 60_000,
          // A job whose server died is run again once, then failed (onJobLost marks the row).
          maxStalledCount: 1,
        }
      );
      worker.on?.('error', (err) => warnThrottled('export_worker_error', err));
      worker.on?.('failed', (job, err) => {
        logger.error('export_worker_job_failed', { exportId: job?.id, error: String(err?.message || err) });
        if (job?.data && onJobLost) {
          Promise.resolve()
            .then(() => onJobLost(job.data, err))
            .catch((hookErr) =>
              logger.error('export_job_lost_handler_failed', { exportId: job?.id, error: String(hookErr?.message || hookErr) })
            );
        }
      });
    }

    bull = { queue, worker, connections };
    mode = 'bullmq';
    logger.info('export_queue_ready', { mode, concurrency: concurrency(), worker: Boolean(worker) });
  } catch (err) {
    await Promise.all(connections.map((c) => Promise.resolve(c.disconnect?.()).catch(() => {})));
    bull = null;
    mode = 'local';
    logger.warn('export_queue_unavailable', {
      error: String(err?.message || err).slice(0, 300),
      fallback: 'exports run in this process',
    });
  }
  return mode;
}

/** Add an export job. Runs it in this process when the queue isn't available. */
/** Add an export job. `local: true` runs it in this process even when the queue is up (PPT_EXPORT_V2 off). */
async function enqueue(data, { local = false } = {}) {
  if (!local && mode === 'bullmq' && bull) {
    try {
      await bull.queue.add('export', data, { jobId: data.exportId });
      return 'bullmq';
    } catch (err) {
      logger.warn('export_queue_add_failed', {
        exportId: data.exportId,
        error: String(err?.message || err).slice(0, 300),
        fallback: 'running in this process',
      });
    }
  }
  runLocally(data);
  return 'local';
}

async function findJob(exportId) {
  if (mode !== 'bullmq' || !bull) return null;
  try {
    return await bull.queue.getJob(exportId);
  } catch {
    return null;
  }
}

/**
 * Where an export is in the queue: `state` is 'waiting' | 'active' | 'delayed' | … | null (not
 * in the queue, or unknown), plus the latest progress if known.
 */
async function jobStatus(exportId) {
  if (running.has(exportId)) return { state: 'active', progress: progressById.get(exportId) || null };
  if (waitingLocal.has(exportId)) return { state: 'waiting', progress: null };
  const job = await findJob(exportId);
  if (!job) return { state: null, progress: null };
  let state = null;
  try {
    state = await job.getState();
  } catch {
    state = null;
  }
  const progress = job.progress && typeof job.progress === 'object' ? job.progress : null;
  return { state: state === 'unknown' ? null : state, progress };
}

const WAITING_STATES = new Set(['waiting', 'delayed', 'prioritized', 'waiting-children']);

/**
 * Stop an export: take it off the queue if it hasn't started, or abort it if it runs here.
 * A job running on another instance notices the cancelled row at its next heartbeat.
 */
async function cancel(exportId) {
  const controller = running.get(exportId);
  if (controller) controller.abort();
  let removed = false;
  const job = await findJob(exportId);
  if (job) {
    try {
      if (WAITING_STATES.has(await job.getState())) {
        await job.remove();
        removed = true;
      }
    } catch {
      // Picked up by a worker meanwhile: it sees the cancelled row and stops.
    }
  }
  return { aborted: Boolean(controller), removed };
}

function stats() {
  return {
    mode,
    concurrency: concurrency(),
    worker: mode === 'local' ? true : Boolean(bull?.worker),
    runningHere: running.size,
    waitingHere: waitingLocal.size,
  };
}

/** Counts from Redis (waiting / active / …), for /health/export. */
async function queueCounts() {
  if (mode !== 'bullmq' || !bull) return null;
  try {
    return await withTimeout(bull.queue.getJobCounts('waiting', 'active', 'delayed', 'failed'), 2_000, 'Job counts');
  } catch {
    return null;
  }
}

/**
 * Shutdown: stop taking jobs. Jobs still running here are left to BullMQ, which hands them to
 * the next worker (they are "stalled" once this process is gone).
 */
async function close() {
  const current = bull;
  bull = null;
  mode = 'local';
  starting = null;
  if (!current) return;
  await Promise.resolve(current.worker?.close(true)).catch(() => {});
  await Promise.resolve(current.queue.close()).catch(() => {});
  await Promise.all(current.connections.map((c) => Promise.resolve(c.quit?.()).catch(() => {})));
}

module.exports = {
  QUEUE_NAME,
  setProcessor,
  setOnJobLost,
  start,
  enqueue,
  jobStatus,
  cancel,
  stats,
  queueCounts,
  close,
};
