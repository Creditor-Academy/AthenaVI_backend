const test = require('node:test');
const assert = require('node:assert/strict');

const { buildRemotionRenderOptions } = require('./renderOptions');
const { createSerialQueue } = require('./renderQueue');

test('render options: unset env keeps Remotion defaults', () => {
  assert.deepEqual(buildRemotionRenderOptions({}), {});
});

test('render options: valid env values are passed through', () => {
  assert.deepEqual(
    buildRemotionRenderOptions({
      REMOTION_CONCURRENCY: ' 2 ',
      REMOTION_X264_PRESET: 'VeryFast',
      REMOTION_CHROMIUM_GL: 'swangle',
    }),
    { concurrency: 2, x264Preset: 'veryfast', chromiumOptions: { gl: 'swangle' } }
  );
});

test('render options: invalid env values are ignored', () => {
  for (const concurrency of ['0', '-1', '1.5', '50%', 'two', '']) {
    assert.deepEqual(
      buildRemotionRenderOptions({
        REMOTION_CONCURRENCY: concurrency,
        REMOTION_X264_PRESET: 'turbo',
        REMOTION_CHROMIUM_GL: 'metal',
      }),
      {},
      `concurrency ${JSON.stringify(concurrency)}`
    );
  }
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

test('render queue: second task starts only after the first settles', async () => {
  const queue = createSerialQueue();
  const first = deferred();
  const events = [];

  const firstRun = queue.enqueue(async () => {
    events.push('first:start');
    await first.promise;
    events.push('first:end');
    return 'a';
  });
  const secondRun = queue.enqueue(async () => {
    events.push('second:start');
    return 'b';
  });

  await tick();
  assert.deepEqual(events, ['first:start']);
  assert.equal(queue.size(), 2);

  first.resolve();
  assert.equal(await firstRun, 'a');
  assert.equal(await secondRun, 'b');
  assert.deepEqual(events, ['first:start', 'first:end', 'second:start']);
  await tick();
  assert.equal(queue.size(), 0);
});

test('render queue: a failed task does not block the next one', async () => {
  const queue = createSerialQueue();
  const first = deferred();
  const events = [];

  const firstRun = queue.enqueue(async () => {
    events.push('first:start');
    await first.promise;
  });
  const secondRun = queue.enqueue(async () => {
    events.push('second:start');
    return 'ok';
  });

  await tick();
  assert.deepEqual(events, ['first:start']);

  first.reject(new Error('boom'));
  await assert.rejects(firstRun, /boom/);
  assert.equal(await secondRun, 'ok');
  assert.deepEqual(events, ['first:start', 'second:start']);
});

test('render queue: a task that throws synchronously does not block the next one', async () => {
  const queue = createSerialQueue();
  const firstRun = queue.enqueue(() => {
    throw new Error('sync boom');
  });
  const secondRun = queue.enqueue(() => 'ok');

  await assert.rejects(firstRun, /sync boom/);
  assert.equal(await secondRun, 'ok');
});
