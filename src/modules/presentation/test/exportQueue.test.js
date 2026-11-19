'use strict';

// The export queue's BullMQ side, against a small in-memory stand-in for BullMQ and ioredis
// (no Redis needed). It checks how the queue uses them: job ids, the worker, progress, cancel,
// and the fallbacks to running exports in this process.

const assert = require('assert');
const { test, afterEach } = require('node:test');

process.env.PPT_EXPORT_CONCURRENCY = '3';

const exportQueue = require('../exportQueue');

/** A stand-in for BullMQ: jobs live in a Map; the worker is driven by the test. */
function fakeBullmq({ failReady = false, failAdd = false } = {}) {
  const jobs = new Map();
  const made = { queues: [], workers: [], redis: [] };
  class FakeJob {
    constructor(id, data) {
      this.id = id;
      this.data = data;
      this.state = 'waiting';
      this.progress = 0;
    }
    async getState() {
      return this.state;
    }
    async remove() {
      if (this.state === 'active') throw new Error('Job is locked');
      jobs.delete(this.id);
      this.state = 'removed';
    }
    async updateProgress(p) {
      this.progress = p;
    }
  }
  class Queue {
    constructor(name, opts) {
      this.name = name;
      this.opts = opts;
      made.queues.push(this);
    }
    on() {}
    async waitUntilReady() {
      if (failReady) throw new Error('connect ECONNREFUSED 127.0.0.1:6379');
    }
    async add(name, data, opts) {
      if (failAdd) throw new Error("Stream isn't writeable and enableOfflineQueue options is false");
      const job = new FakeJob(opts.jobId, data);
      jobs.set(opts.jobId, job);
      return job;
    }
    async getJob(id) {
      return jobs.get(id) || null;
    }
    async getJobCounts() {
      return { waiting: [...jobs.values()].filter((j) => j.state === 'waiting').length, active: 0, delayed: 0, failed: 0 };
    }
    async close() {
      this.closed = true;
    }
  }
  class Worker {
    constructor(name, processor, opts) {
      this.name = name;
      this.processor = processor;
      this.opts = opts;
      made.workers.push(this);
      this.handlers = {};
    }
    on(event, fn) {
      this.handlers[event] = fn;
    }
    /** What BullMQ does when it gives up on a job (stalled twice, or the processor threw). */
    fail(id, err) {
      const job = jobs.get(id);
      job.state = 'failed';
      this.handlers.failed?.(job, err, 'active');
    }
    /** What BullMQ does when it picks a job up. */
    async take(id) {
      const job = jobs.get(id);
      job.state = 'active';
      try {
        return await this.processor(job);
      } finally {
        job.state = 'completed';
      }
    }
    async close(force) {
      this.closed = force ? 'force' : 'graceful';
    }
  }
  class FakeRedis {
    constructor(url, opts) {
      this.url = url;
      this.opts = opts;
      made.redis.push(this);
    }
    on() {}
    disconnect() {
      this.disconnected = true;
    }
    async quit() {
      this.quit_ = true;
    }
  }
  return { bullmq: { Queue, Worker }, IORedis: FakeRedis, jobs, made };
}

afterEach(async () => {
  await exportQueue.close();
  delete process.env.REDIS_URL;
  delete process.env.PPT_EXPORT_QUEUE;
  delete process.env.PPT_EXPORT_WORKER;
});

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('with Redis: jobs go to the presentation-export queue, keyed by export id, and the worker runs them', async () => {
  process.env.REDIS_URL = 'redis://queue.test:6379';
  const fake = fakeBullmq();
  const seen = [];
  exportQueue.setProcessor(async (data, { signal, onProgress }) => {
    seen.push(data.exportId);
    assert.ok(signal instanceof AbortSignal);
    onProgress({ stage: 'drawing', percent: 50, done: 1, total: 2 });
    return 'READY';
  });
  assert.equal(await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis }), 'bullmq');

  const [queue] = fake.made.queues;
  const [worker] = fake.made.workers;
  assert.equal(queue.name, 'presentation-export');
  assert.equal(queue.opts.defaultJobOptions.attempts, 1, 'crash retries happen inside the job');
  assert.equal(queue.opts.connection.opts.enableOfflineQueue, false, 'adding fails fast when Redis is down');
  assert.equal(queue.opts.connection.opts.maxRetriesPerRequest, null);
  assert.equal(worker.opts.concurrency, 3, 'PPT_EXPORT_CONCURRENCY');
  assert.equal(worker.opts.maxStalledCount, 1, 'a job whose server died runs again once');
  assert.notEqual(worker.opts.connection, queue.opts.connection, 'the worker has its own connection');

  assert.equal(await exportQueue.enqueue({ exportId: 'e1', format: 'PDF' }), 'bullmq');
  assert.deepEqual(fake.jobs.get('e1').data, { exportId: 'e1', format: 'PDF' });
  assert.deepEqual(await exportQueue.jobStatus('e1'), { state: 'waiting', progress: null });

  assert.equal(await worker.take('e1'), 'READY');
  assert.deepEqual(seen, ['e1']);
  assert.deepEqual(fake.jobs.get('e1').progress, { stage: 'drawing', percent: 50, done: 1, total: 2 }, 'progress kept on the job');
  assert.deepEqual(await exportQueue.queueCounts(), { waiting: 0, active: 0, delayed: 0, failed: 0 });
});

test('with Redis: progress of a running job is visible, and cancel aborts it', async () => {
  process.env.REDIS_URL = 'redis://queue.test:6379';
  const fake = fakeBullmq();
  let release;
  exportQueue.setProcessor(
    (data, { signal, onProgress }) =>
      new Promise((resolve) => {
        onProgress({ stage: 'drawing', percent: 30, done: 1, total: 4 });
        signal.addEventListener('abort', () => resolve('CANCELLED'));
        release = () => resolve('READY');
      })
  );
  await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis });
  await exportQueue.enqueue({ exportId: 'e2' });
  const running = fake.made.workers[0].take('e2');
  await wait(5);
  assert.deepEqual(await exportQueue.jobStatus('e2'), {
    state: 'active',
    progress: { stage: 'drawing', percent: 30, done: 1, total: 4 },
  });
  assert.deepEqual(await exportQueue.cancel('e2'), { aborted: true, removed: false });
  assert.equal(await running, 'CANCELLED');
  assert.equal(exportQueue.stats().runningHere, 0);
  release();
});

test('with Redis: cancelling a job that is still waiting takes it off the queue', async () => {
  process.env.REDIS_URL = 'redis://queue.test:6379';
  const fake = fakeBullmq();
  exportQueue.setProcessor(async () => 'READY');
  await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis });
  await exportQueue.enqueue({ exportId: 'e3' });
  assert.deepEqual(await exportQueue.cancel('e3'), { aborted: false, removed: true });
  assert.equal(fake.jobs.has('e3'), false);
  assert.deepEqual(await exportQueue.jobStatus('e3'), { state: null, progress: null });
});

test('Redis unreachable at boot: exports run in this process', async () => {
  process.env.REDIS_URL = 'redis://down.test:6379';
  const fake = fakeBullmq({ failReady: true });
  const ran = [];
  exportQueue.setProcessor(async (data) => {
    ran.push(data.exportId);
    return 'READY';
  });
  assert.equal(await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis }), 'local');
  assert.ok(fake.made.redis.every((c) => c.disconnected), 'no reconnect loop left behind');
  assert.equal(await exportQueue.enqueue({ exportId: 'e4' }), 'local');
  await wait(10);
  assert.deepEqual(ran, ['e4']);
});

test('Redis down when adding a job: that export runs in this process instead', async () => {
  process.env.REDIS_URL = 'redis://queue.test:6379';
  const fake = fakeBullmq({ failAdd: true });
  const ran = [];
  exportQueue.setProcessor(async (data) => {
    ran.push(data.exportId);
    return 'READY';
  });
  assert.equal(await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis }), 'bullmq');
  assert.equal(await exportQueue.enqueue({ exportId: 'e5' }), 'local');
  await wait(10);
  assert.deepEqual(ran, ['e5']);
});

test('PPT_EXPORT_WORKER=0: this instance only adds jobs; PPT_EXPORT_QUEUE=local: no Redis at all', async () => {
  process.env.REDIS_URL = 'redis://queue.test:6379';
  process.env.PPT_EXPORT_WORKER = '0';
  const fake = fakeBullmq();
  exportQueue.setProcessor(async () => 'READY');
  await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis });
  assert.equal(fake.made.workers.length, 0);
  assert.equal(exportQueue.stats().worker, false);
  await exportQueue.close();

  process.env.PPT_EXPORT_QUEUE = 'local';
  const other = fakeBullmq();
  assert.equal(await exportQueue.start({ bullmq: other.bullmq, IORedis: other.IORedis }), 'local');
  assert.equal(other.made.queues.length, 0);
});

test('shutdown closes the worker without waiting (its jobs are picked up again after restart)', async () => {
  process.env.REDIS_URL = 'redis://queue.test:6379';
  const fake = fakeBullmq();
  exportQueue.setProcessor(async () => 'READY');
  await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis });
  await exportQueue.close();
  assert.equal(fake.made.workers[0].closed, 'force');
  assert.equal(fake.made.queues[0].closed, true);
  assert.equal(exportQueue.stats().mode, 'local');
});

test('a job BullMQ gives up on (its server died twice) is handed to the lost-job handler', async () => {
  process.env.REDIS_URL = 'redis://queue.test:6379';
  const fake = fakeBullmq();
  const lost = [];
  exportQueue.setProcessor(async () => 'READY');
  exportQueue.setOnJobLost(async (data, err) => lost.push({ data, error: err.message }));
  await exportQueue.start({ bullmq: fake.bullmq, IORedis: fake.IORedis });
  await exportQueue.enqueue({ exportId: 'e9', userId: 'u1' });
  fake.made.workers[0].fail('e9', new Error('job stalled more than allowable limit'));
  await wait(10);
  assert.deepEqual(lost, [{ data: { exportId: 'e9', userId: 'u1' }, error: 'job stalled more than allowable limit' }]);
  assert.deepEqual(await exportQueue.jobStatus('e9'), { state: 'failed', progress: null });
  exportQueue.setOnJobLost(null);
});

test('in-process: a job that throws is handed to the lost-job handler too', async () => {
  process.env.PPT_EXPORT_QUEUE = 'local';
  const lost = [];
  exportQueue.setProcessor(async () => {
    throw new Error('database went away');
  });
  exportQueue.setOnJobLost(async (data, err) => lost.push({ id: data.exportId, error: err.message }));
  await exportQueue.start();
  assert.equal(await exportQueue.enqueue({ exportId: 'e10' }), 'local');
  await wait(20);
  assert.deepEqual(lost, [{ id: 'e10', error: 'database went away' }]);
  exportQueue.setOnJobLost(null);
});
