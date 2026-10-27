const test = require('node:test');
const assert = require('node:assert/strict');

const {
  clampRatio,
  mapRange,
  remotionProgressRatio,
  createProgressReporter,
} = require('./renderProgress');

test('mapRange: interpolates and clamps', () => {
  assert.equal(mapRange(0, 5, 70), 5);
  assert.equal(mapRange(1, 5, 70), 70);
  assert.equal(mapRange(0.5, 70, 99), 85);
  assert.equal(mapRange(-1, 5, 70), 5);
  assert.equal(mapRange(2, 5, 70), 70);
});

test('remotionProgressRatio: reads event.progress', () => {
  assert.equal(remotionProgressRatio({ progress: 0.4 }), 0.4);
  assert.equal(remotionProgressRatio({ progress: 2 }), 1);
  assert.equal(remotionProgressRatio(null), 0);
  assert.equal(remotionProgressRatio({}), 0);
});

test('clampRatio: rejects non-numeric values', () => {
  assert.equal(clampRatio('nope'), 0);
  assert.equal(clampRatio(undefined), 0);
});

test('progress reporter: throttles writes and never reports 100', async () => {
  const seen = [];
  const { report, lastProgress } = createProgressReporter({
    persist: async (progress) => {
      seen.push(progress);
    },
    minIntervalMs: 10_000,
  });

  await report(12);
  await report(13);
  await report(150);

  assert.deepEqual(seen, [12, 99]);
  assert.equal(lastProgress(), 99);
});

test('progress reporter: ignores equal or lower values', async () => {
  const seen = [];
  const { report } = createProgressReporter({
    persist: async (progress) => {
      seen.push(progress);
    },
    minIntervalMs: 0,
  });

  await report(20);
  await report(20);
  await report(15);
  await report(21);

  assert.deepEqual(seen, [20, 21]);
});
